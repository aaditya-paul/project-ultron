import sys
import os
import json

from colors import CYAN, RED, GRN, WHT, DIM, YLW, RST, BOLD
from banner import banner
from cloner import clone_repo, list_repos, delete_repo, delete_all_repos, repo_exists, repo_path, extract_repo_name, get_remote_url
from detector import analyze_project, show_detected_types, save_workspace_manifest, WORKSPACE_DIR
from parser import parse_repo, save_ast, show_parse_summary
from graph import load_ast, build_graph, save_graph, render_graph, show_graph_summary, run_security_pipeline
from security_graph import show_security_graph_summary, build_security_graph
from rules import show_findings
from help import show_help
from llm_client import LocalLLMClient, CloudLLMClient, load_config, create_llm_client, CLOUD_PROVIDER_NAMES
from taint_graph import render_taint_graph
from entities import extract_entities
from llm_detector import run_llm_detection

try:
    from extractors.js_ts import JsTsExtractor
    from extractors.adapter import inject_ir_into_ast
    _HAS_IR = True
except ImportError:
    _HAS_IR = False

def _run_ir_pipeline(target: str, ast_data: dict) -> dict:
    """Run IR extractor on JS/TS files and inject into ast_data."""
    if not _HAS_IR:
        print(f"  {YLW}[!]{RST} IR extractor not available (tree-sitter missing?)")
        return ast_data

    extractor = JsTsExtractor()
    ir_modules = []
    total_ir_funcs = 0

    for fpath, info in ast_data.get("files", {}).items():
        lang = info.get("language", "")
        if lang not in ("TypeScript", "JavaScript", "TSX"):
            continue
        full_path = os.path.join(target, fpath)
        if not os.path.isfile(full_path):
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            continue
        mod = extractor.extract(source, fpath, lang)
        if mod:
            ir_modules.append(mod)
            total_ir_funcs += len(mod.functions)

    if ir_modules:
        legacy_count = sum(
            1 for info in ast_data.get("files", {}).values()
            for fn in info.get("functions", [])
        )
        inject_ir_into_ast(ir_modules, ast_data)
        print(f"  {GRN}[+]{RST} IR pipeline: {WHT}{len(ir_modules)}{RST} files, {WHT}{total_ir_funcs}{RST} functions (legacy: {legacy_count})")
    else:
        print(f"  {DIM}[*]{RST} IR pipeline: no JS/TS files to process")

    return ast_data


def print_terminal_graphs(dependency_graph, security_graph):
    # 1. Print Dependency Graph
    print(f"\n  {CYAN}{BOLD}DEPENDENCY GRAPH (TERMINAL VIEW){RST}")
    print(f"  {DIM}──────────────────────────────────────────────────{RST}")
    
    files = [n for n in dependency_graph["nodes"] if n["type"] == "file"]
    functions = [n for n in dependency_graph["nodes"] if n["type"] == "function"]
    
    print(f"    {BOLD}Files ({len(files)}):{RST}")
    for f in files[:10]:
        print(f"      • {WHT}{f['label']}{RST} ({f['language']}, {f['layer']})")
    if len(files) > 10:
        print(f"      ... and {len(files) - 10} more files")
        
    print(f"\n    {BOLD}Functions ({len(functions)}):{RST}")
    by_role = {}
    for fn in functions:
        by_role.setdefault(fn.get("security_role", "other"), []).append(fn)
        
    for role, fns in sorted(by_role.items()):
        print(f"      {GRN}• {role.upper()} ({len(fns)}):{RST}")
        for fn in fns[:5]:
            print(f"        - {WHT}{fn['label']}{RST} [{fn['file']}:{fn['line']}]")
        if len(fns) > 5:
            print(f"        ... and {len(fns) - 5} more")
            
    print(f"\n    {BOLD}Connections:{RST}")
    edges = dependency_graph.get("edges", [])
    calls = [e for e in edges if e["type"] == "call"]
    imports = [e for e in edges if e["type"] == "import"]
    
    print(f"      {GRN}• Imports ({len(imports)}):{RST}")
    for imp in imports[:8]:
        src_label = imp["source"].split(":")[-1]
        tgt_label = imp["target"].split(":")[-1]
        print(f"        - {src_label} {DIM}imports{RST} {tgt_label}")
    if len(imports) > 8:
        print(f"        ... and {len(imports) - 8} more")
        
    print(f"      {GRN}• Function Calls ({len(calls)}):{RST}")
    for call in calls[:8]:
        src_label = call["source"].split("::")[-1]
        tgt_label = call["target"].split("::")[-1]
        print(f"        - {src_label} {DIM}calls{RST} {tgt_label}")
    if len(calls) > 8:
        print(f"        ... and {len(calls) - 8} more")

    # 2. Print Taint Flow Paths
    print(f"\n  {CYAN}{BOLD}TAINT PROPAGATION PATHS (TERMINAL VIEW){RST}")
    print(f"  {DIM}──────────────────────────────────────────────────{RST}")
    
    flows = security_graph.get("flows", [])
    if not flows:
        print(f"    {DIM}No taint propagation flows detected.{RST}")
    else:
        for idx, flow in enumerate(flows):
            print(f"    {BOLD}Path #{idx+1}: {flow['source']} ──► {flow['sink_type']}{RST}")
            labels = flow.get("path_labels", [])
            path_str = f"      "
            for step_idx, step in enumerate(labels):
                if step_idx == 0:
                    path_str += f"{RED}[SOURCE] {step}{RST}"
                elif step_idx == len(labels) - 1:
                    path_str += f" ──► {RED}[SINK] {step}{RST}"
                else:
                    path_str += f" ──► {YLW}{step}{RST}"
            print(path_str)
            
            exprs = flow.get("expressions", [])
            if exprs:
                print(f"      {DIM}Transformations:{RST}")
                for ex in exprs:
                    print(f"        └─ {DIM}{ex}{RST}")
            
            san_status = f"{GRN}SANITIZED (via {', '.join(flow['validators'])}){RST}" if flow["validated"] else f"{RED}UNSANITIZED{RST}"
            print(f"      {BOLD}Status:{RST} {san_status}\n")
    print(f"  {DIM}──────────────────────────────────────────────────{RST}\n")

def run_analysis_and_report(name, ast_data, verbose=False):
    out_dir = os.path.join(WORKSPACE_DIR, name, "graph")
    os.makedirs(out_dir, exist_ok=True)

    config = load_config()
    mode = os.environ.get("ULTRON_LLM_MODE") or config.get("llm_mode", "local")

    print(f"  {CYAN}[*]{RST} initializing {mode} LLM client for classification...")
    classifier_client = create_llm_client(part="classifier")
    detector_client = None

    if mode == "cloud":
        if classifier_client.is_available():
            chain = classifier_client._get_chain()
            providers = ", ".join(CLOUD_PROVIDER_NAMES.get(p, p) for p in chain)
            print(f"  {GRN}[+]{RST} cloud providers configured: {WHT}{providers}{RST} (model: {classifier_client.model})")
            print(f"  {CYAN}[*]{RST} initializing cloud LLM client for vulnerability detection...")
            detector_client = create_llm_client(part="detector")
            if detector_client.is_available():
                dchain = detector_client._get_chain()
                dproviders = ", ".join(CLOUD_PROVIDER_NAMES.get(p, p) for p in dchain)
                print(f"  {GRN}[+]{RST} cloud providers configured for detection: {WHT}{dproviders}{RST} (model: {detector_client.model})")
            else:
                print(f"  {YLW}[!]{RST} no API keys configured for detector — using deterministic rules")
        else:
            print(f"  {YLW}[!]{RST} no cloud providers configured — set api_keys in config")
            print(f"  {YLW}[!]{RST} running in pattern-only mode (reduced accuracy)")
            classifier_client = None
    else:
        if classifier_client.is_available():
            if classifier_client._detect_api() == "ollama" and not classifier_client.is_model_available():
                print(f"  {YLW}[!]{RST} Ollama server active, but model {WHT}'{classifier_client.model}'{RST} is not pulled.")
                print(f"      To pull it, run: {GRN}ollama pull {classifier_client.model}{RST}")
                print(f"      Running in pattern-only mode (reduced accuracy).")
                classifier_client = None
            else:
                print(f"  {GRN}[+]{RST} local LLM server active for classification: {WHT}{classifier_client.base_url}{RST} (model: {classifier_client.model})")
                print(f"  {CYAN}[*]{RST} initializing local LLM client for vulnerability detection...")
                detector_client = create_llm_client(part="detector")
                if detector_client.is_available() and detector_client._detect_api() == "ollama" and not detector_client.is_model_available():
                    print(f"  {YLW}[!]{RST} Ollama server active, but detector model {WHT}'{detector_client.model}'{RST} is not pulled.")
                    print(f"      To pull it, run: {GRN}ollama pull {detector_client.model}{RST}")
                    print(f"      Using deterministic flow rules (fallback).")
                    detector_client = None
                elif detector_client.is_available():
                    print(f"  {GRN}[+]{RST} local LLM server active for vulnerability detection: {WHT}{detector_client.base_url}{RST} (model: {detector_client.model})")
        else:
            print(f"  {YLW}[!]{RST} no LLM available — classification is pattern-only (reduced accuracy)")
            classifier_client = None

    print(f"  {CYAN}[*]{RST} running hybrid security analysis...")
    pipeline = run_security_pipeline(ast_data, classifier_client, verbose=verbose)
    
    # Run LLM vulnerability detection on flows
    final_findings = []
    
    # Extract route/authentication/etc. deterministic findings (not unvalidated flow-based ones, to let LLM handle flow verification)
    route_findings = [f for f in pipeline["findings"] if f["rule"] in ("missing-authentication", "database-write-without-validation", "exposed-network-request")]
    final_findings.extend(route_findings)
    
    if detector_client and detector_client.is_available():
        llm_findings = run_llm_detection(name, pipeline["security_graph"], detector_client, verbose=verbose)
        final_findings.extend(llm_findings)
    else:
        # Fallback: keep all deterministic findings if LLM detector isn't available
        flow_findings = [f for f in pipeline["findings"] if f["rule"] not in ("missing-authentication", "database-write-without-validation", "exposed-network-request")]
        final_findings.extend(flow_findings)
    
    spath = os.path.join(out_dir, "security_graph.json")
    with open(spath, "w", encoding="utf-8") as f:
        json.dump({
            "entities": pipeline["entities"],
            "security_graph": pipeline["security_graph"],
            "findings": final_findings,
        }, f, indent=2, ensure_ascii=False)
    print(f"  {DIM}[*]{RST} security graph saved -> {WHT}{spath}{RST}")

    # Show classification statistics
    stats = getattr(extract_entities, "stats", {})
    if stats:
        pattern_count = stats.get("pattern_classified", 0)
        llm_count = stats.get("llm_classified", 0)
        unclassified_count = stats.get("unclassified", 0)
        print(f"  {DIM}[*]{RST} classification: {GRN}{pattern_count}{RST} pattern-classified, {GRN}{llm_count}{RST} LLM-classified, {GRN}{unclassified_count}{RST} unclassified")

    show_security_graph_summary(pipeline["security_graph"])
    show_findings(final_findings)

    if os.environ.get("ULTRON_VISUALISE") == "1":
        dependency_graph = build_graph(ast_data)
        print_terminal_graphs(dependency_graph, pipeline["security_graph"])

def analyze_and_save(repo_url, repo_name):
    target = repo_path(repo_name)
    print(f"  {DIM}[*]{RST} switched to {WHT}{target}{RST}")
    print()
    analysis = analyze_project(target)
    show_detected_types(repo_name, analysis)

    manifest = save_workspace_manifest(repo_name, repo_url, analysis)
    print(f"  {DIM}[*]{RST} workspace saved -> {WHT}{manifest}{RST}")

    print(f"  {CYAN}[*]{RST} parsing AST...")
    ast_data = parse_repo(target)
    if os.environ.get("ULTRON_IR") == "1":
        ast_data = _run_ir_pipeline(target, ast_data)
    ast_path = save_ast(WORKSPACE_DIR, repo_name, ast_data)
    if ast_path:
        show_parse_summary(repo_name, ast_data)
        print(f"  {DIM}[*]{RST} AST saved -> {WHT}{ast_path}{RST}")
        print()
        run_analysis_and_report(repo_name, ast_data)

def cmd_clone(url):
    repo_name = clone_repo(url)
    if not repo_name:
        return False

    analyze_and_save(url, repo_name)
    return True

def cmd_scan(name):
    if not repo_exists(name):
        print(f"  {RED}[-]{RST} {WHT}{name}{RST} not found in clones/. clone it first.")
        return
    target = repo_path(name)
    remote_url = get_remote_url(name) or f"clones/{name}"
    print(f"  {DIM}[*]{RST} switched to {WHT}{target}{RST}")
    print()
    analysis = analyze_project(target)
    show_detected_types(name, analysis)
    manifest = save_workspace_manifest(name, remote_url, analysis)
    print(f"  {DIM}[*]{RST} workspace saved -> {WHT}{manifest}{RST}")

    print(f"  {CYAN}[*]{RST} parsing AST...")
    ast_data = parse_repo(target)
    if os.environ.get("ULTRON_IR") == "1":
        ast_data = _run_ir_pipeline(target, ast_data)
    ast_path = save_ast(WORKSPACE_DIR, name, ast_data)
    if ast_path:
        show_parse_summary(name, ast_data)
        print(f"  {DIM}[*]{RST} AST saved -> {WHT}{ast_path}{RST}")
        print()
        run_analysis_and_report(name, ast_data)

def cmd_visualise(name):
    os.environ["ULTRON_VISUALISE"] = "1"
    ast_data = load_ast(WORKSPACE_DIR, name)
    if not ast_data:
        print(f"  {YLW}[!]{RST} no AST data. run scan first.")
        return

    print(f"  {CYAN}[*]{RST} building dependency graph...")
    graph = build_graph(ast_data)
    gpath = save_graph(WORKSPACE_DIR, name, graph)
    show_graph_summary(graph)
    if gpath:
        print(f"  {DIM}[*]{RST} graph saved -> {WHT}{gpath}{RST}")

    out_dir = os.path.join(WORKSPACE_DIR, name, "graph")
    out_path = os.path.join(out_dir, "dependency_graph.svg")
    vis_path = render_graph(graph, out_path)
    if vis_path:
        print(f"  {GRN}[+]{RST} dependency visualisation saved -> {WHT}{vis_path}{RST}")

    print()
    run_analysis_and_report(name, ast_data)

    # Render taint propagation graph
    taint_paths = getattr(build_security_graph, "taint_paths", [])
    if taint_paths:
        taint_out_path = os.path.join(out_dir, "taint_graph.svg")
        tvis_path = render_taint_graph(taint_paths, taint_out_path)
        if tvis_path:
            print(f"  {GRN}[+]{RST} taint propagation visualisation saved -> {WHT}{tvis_path}{RST}")

def cmd_delete(args):
    if len(args) == 0:
        print(f"  {RED}[-]{RST} specify a repo name or {WHT}--all{RST}")
        return
    if args[0] == "--all":
        delete_all_repos()
    else:
        delete_repo(args[0])

def cmd_config(args):
    config_path = "ultron_config.json"
    config = load_config()
    
    if len(args) == 0:
        # Show configuration
        print(f"\n  {CYAN}{BOLD}ULTRON CONFIGURATION{RST}")
        print(f"  {DIM}──────────────────────────────────────────────────{RST}")
        print(f"    {BOLD}llm_mode{RST}     : {WHT}{config.get('llm_mode', 'local')}{RST}")
        print(f"    {BOLD}llm_url{RST}      : {WHT}{config.get('llm_url')}{RST}")
        print(f"    {BOLD}llm_model{RST}    : {WHT}{config.get('llm_model')}{RST}")
        print(f"    {BOLD}temperature{RST}  : {WHT}{config.get('temperature')}{RST}")
        print(f"    {BOLD}max_tokens{RST}   : {WHT}{config.get('max_tokens')}{RST}")
        print(f"    {BOLD}timeout{RST}      : {WHT}{config.get('timeout')}{RST}")
        print(f"    {BOLD}num_workers{RST}  : {WHT}{config.get('num_workers')}{RST}")
        print(f"    {BOLD}version{RST}      : {WHT}{config.get('version')}{RST}")
        print(f"    {BOLD}verbose{RST}      : {WHT}{config.get('verbose', False)}{RST}")
        print(f"    {BOLD}visualise{RST}    : {WHT}{config.get('visualise', False)}{RST}")

        # Display cloud provider info
        api_keys = config.get("api_keys", {})
        configured = [k for k, v in api_keys.items() if v]
        if configured:
            print(f"\n  {CYAN}{BOLD}CLOUD PROVIDERS{RST}")
            print(f"  {DIM}──────────────────────────────────────────────────{RST}")
            print(f"    {BOLD}api_keys{RST}     : {WHT}{', '.join(configured)}{RST}")
            chain = config.get("cloud_chain", {})
            for part, providers in chain.items():
                print(f"    {BOLD}{part:<12}{RST} : {WHT}{' -> '.join(providers)}{RST}")
            models = config.get("cloud_models", {})
            for prov, model in models.items():
                if prov in configured:
                    print(f"    {BOLD}{prov:<12}{RST} : {WHT}{model}{RST}")
        
        # Display parts overrides
        print(f"\n  {CYAN}{BOLD}SPECIFIC LLM PARTS OVERRIDES{RST}")
        print(f"  {DIM}──────────────────────────────────────────────────{RST}")
        overrides = config.get("model_overrides", {})
        if overrides:
            for part, model in overrides.items():
                print(f"    {BOLD}{part:<12}{RST} : {WHT}{model}{RST}")
        else:
            print(f"    {DIM}none set{RST}")
            
        print(f"\n  {DIM}To change a model override, run: {GRN}config <part> <model-name>{RST}")
        print(f"  {DIM}To change a setting, run: {GRN}config <setting> <value>{RST} (e.g. config visualise true)")
        print(f"  {DIM}To reset configuration to defaults, run: {GRN}config reset{RST}\n")
        return

    if len(args) == 1 and args[0].lower() == "reset":
        default_config = {
            "llm_url": "http://localhost:11434",
            "llm_model": "qwen2.5-coder:3b",
            "temperature": 0.1,
            "max_tokens": 1024,
            "num_workers": 5,
            "timeout": 60.0,
            "version": "8.0.0",
            "verbose": False,
            "visualise": False,
            "llm_mode": "local",
            "model_overrides": {
                "classifier": "qwen2.5-coder:3b",
                "detector": "qwen2.5-coder:3b",
                "exploiter": "qwen2.5-coder:3b",
                "reporter": "qwen2.5-coder:3b"
            },
            "api_keys": {"groq": "", "gemini": "", "nvidia": ""},
            "cloud_chain": {"default": ["groq", "gemini", "nvidia"]},
            "cloud_models": {"groq": "llama-3.3-70b-versatile", "gemini": "gemini-2.0-flash", "nvidia": "meta/llama-3.1-8b-instruct"}
        }
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            print(f"  {GRN}[+]{RST} configuration reset to defaults successfully.")
            print(f"  {DIM}[*]{RST} saved configuration to {WHT}{config_path}{RST}")
        except Exception as e:
            print(f"  {RED}[-]{RST} failed to reset configuration: {e}")
        return

    if len(args) < 2:
        print(f"  {RED}[-]{RST} usage: config <part/setting> <value> (e.g. config classifier llama3.1:8b or config visualise true)")
        return

    part = args[0].lower()
    val_str = args[1]
    
    valid_parts = {"classifier", "detector", "exploiter", "reporter", "default"}
    valid_settings = {"visualise", "visualize", "verbose", "temperature", "max_tokens", "timeout", "num_workers", "llm_url", "llm_mode"}
    
    if part not in valid_parts and part not in valid_settings:
        print(f"  {RED}[-]{RST} invalid part or setting '{part}'. Valid parts: {', '.join(valid_parts)}, Settings: {', '.join(valid_settings)}")
        return

    if part in valid_settings:
        if part in ("visualise", "visualize"):
            val = val_str.lower() in ("true", "1", "yes", "on", "enable", "enabled")
            config["visualise"] = val
            config["visualize"] = val
            print(f"  {GRN}[+]{RST} setting {BOLD}visualise{RST} updated to {WHT}{val}{RST}")
        elif part == "verbose":
            val = val_str.lower() in ("true", "1", "yes", "on", "enable", "enabled")
            config["verbose"] = val
            print(f"  {GRN}[+]{RST} setting {BOLD}verbose{RST} updated to {WHT}{val}{RST}")
        elif part in ("temperature", "timeout"):
            try:
                val = float(val_str)
                config[part] = val
                print(f"  {GRN}[+]{RST} setting {BOLD}{part}{RST} updated to {WHT}{val}{RST}")
            except ValueError:
                print(f"  {RED}[-]{RST} invalid float value for {part}: {val_str}")
                return
        elif part in ("max_tokens", "num_workers"):
            try:
                val = int(val_str)
                config[part] = val
                print(f"  {GRN}[+]{RST} setting {BOLD}{part}{RST} updated to {WHT}{val}{RST}")
            except ValueError:
                print(f"  {RED}[-]{RST} invalid integer value for {part}: {val_str}")
                return
        elif part == "llm_mode":
            val = val_str.lower()
            if val not in ("local", "cloud"):
                print(f"  {RED}[-]{RST} invalid llm_mode '{val_str}'. Use 'local' or 'cloud'.")
                return
            config[part] = val
            print(f"  {GRN}[+]{RST} setting {BOLD}llm_mode{RST} updated to {WHT}{val}{RST}")
        elif part == "llm_url":
            config[part] = val_str
            print(f"  {GRN}[+]{RST} setting {BOLD}{part}{RST} updated to {WHT}{val_str}{RST}")
    else:
        if part == "default":
            config["llm_model"] = val_str
            print(f"  {GRN}[+]{RST} default model updated to {WHT}'{val_str}'{RST}")
        else:
            overrides = config.setdefault("model_overrides", {})
            overrides[part] = val_str
            print(f"  {GRN}[+]{RST} model override for {BOLD}{part}{RST} updated to {WHT}'{val_str}'{RST}")

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"  {DIM}[*]{RST} saved configuration to {WHT}{config_path}{RST}")
    except Exception as e:
        print(f"  {RED}[-]{RST} failed to save configuration: {e}")

def interactive():
    while True:
        line = input(f"  {CYAN}[~]{RST} target repository : ").strip()
        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower() if parts else ""

        # Check for debug flags in interactive line
        debug_flags = {"--debug", "-d", "--verbose", "-v"}
        cmd_debug = any(p in debug_flags for p in parts)
        
        if cmd_debug or os.environ.get("ULTRON_GLOBAL_DEBUG") == "1":
            os.environ["ULTRON_DEBUG"] = "1"
            if cmd_debug:
                print(f"  {CYAN}[*]{RST} Debug/Verbose mode enabled for this command")
            parts = [p for p in parts if p not in debug_flags]
            # Reconstruct clean line without debug flags
            line = " ".join(parts)
            cmd = parts[0].lower() if parts else ""
        else:
            if "ULTRON_DEBUG" in os.environ:
                del os.environ["ULTRON_DEBUG"]

        # Check for visualise flags in interactive line
        vis_flags = {"--visualise", "--visualize", "-vis"}
        cmd_vis = any(p in vis_flags for p in parts)
        
        if cmd_vis or os.environ.get("ULTRON_GLOBAL_VISUALISE") == "1":
            os.environ["ULTRON_VISUALISE"] = "1"
            if cmd_vis:
                print(f"  {CYAN}[*]{RST} Visualisation mode enabled for this command")
            parts = [p for p in parts if p not in vis_flags]
            # Reconstruct clean line without visualise flags
            line = " ".join(parts)
            cmd = parts[0].lower() if parts else ""
        else:
            if "ULTRON_VISUALISE" in os.environ:
                del os.environ["ULTRON_VISUALISE"]

        # Check for --mode flag in interactive line
        mode_flags = {"--mode"}
        mode_idx = None
        for i, p in enumerate(parts):
            if p in mode_flags and i + 1 < len(parts):
                mode_val = parts[i + 1].lower()
                if mode_val in ("local", "cloud"):
                    os.environ["ULTRON_LLM_MODE"] = mode_val
                    print(f"  {CYAN}[*]{RST} LLM mode set to {WHT}{mode_val}{RST}")
                    mode_idx = i
                break
        if mode_idx is not None:
            parts = parts[:mode_idx] + parts[mode_idx + 2:]
            line = " ".join(parts)
            cmd = parts[0].lower() if parts else ""

        # Check for --ir flag in interactive line
        ir_flags = {"--ir"}
        if any(p in ir_flags for p in parts):
            os.environ["ULTRON_IR"] = "1"
            print(f"  {CYAN}[*]{RST} IR pipeline enabled for this command")
            parts = [p for p in parts if p not in ir_flags]
            line = " ".join(parts)
            cmd = parts[0].lower() if parts else ""
        else:
            if "ULTRON_IR" in os.environ:
                del os.environ["ULTRON_IR"]

        if cmd in ("help", "--help", "-h"):
            show_help()
            continue

        if not line or cmd in ("exit", "quit", "bye"):
            print(f"  {RED}[!] exiting.{RST}")
            sys.exit(1)

        if cmd == "list":
            list_repos()
            continue

        if cmd == "config":
            cmd_config(parts[1:])
            continue

        if cmd == "scan":
            if len(parts) < 2:
                print(f"  {RED}[-]{RST} usage: scan <repo-name>")
                continue
            cmd_scan(parts[1])
            continue

        if cmd in ("visualise", "visualize"):
            if len(parts) < 2:
                print(f"  {RED}[-]{RST} usage: visualise <repo-name>")
                continue
            cmd_visualise(parts[1])
            continue

        if cmd == "delete":
            if len(parts) < 2:
                print(f"  {RED}[-]{RST} usage: delete <repo-name> or delete --all")
                continue
            cmd_delete(parts[1:])
            continue

        if not cmd_clone(line):
            print()
            continue

        print()

def main():
    # Load flags from config
    config = load_config()
    if config.get("verbose", False) or config.get("debug", False):
        os.environ["ULTRON_GLOBAL_DEBUG"] = "1"
        os.environ["ULTRON_DEBUG"] = "1"
        
    if config.get("visualise", False) or config.get("visualize", False):
        os.environ["ULTRON_GLOBAL_VISUALISE"] = "1"
        os.environ["ULTRON_VISUALISE"] = "1"

    # Check for debug flags in CLI args
    debug_flags = {"--debug", "-d", "--verbose", "-v"}
    if any(arg in sys.argv for arg in debug_flags):
        os.environ["ULTRON_GLOBAL_DEBUG"] = "1"
        os.environ["ULTRON_DEBUG"] = "1"
        sys.argv = [arg for arg in sys.argv if arg not in debug_flags]

    # Check for visualise flags in CLI args
    vis_flags = {"--visualise", "--visualize", "-vis"}
    if any(arg in sys.argv for arg in vis_flags):
        os.environ["ULTRON_GLOBAL_VISUALISE"] = "1"
        os.environ["ULTRON_VISUALISE"] = "1"
        sys.argv = [arg for arg in sys.argv if arg not in vis_flags]

    # Check for --mode flag in CLI args
    mode_flags = {"--mode"}
    mode_idx = None
    for i, arg in enumerate(sys.argv):
        if arg in mode_flags and i + 1 < len(sys.argv):
            mode_val = sys.argv[i + 1].lower()
            if mode_val in ("local", "cloud"):
                os.environ["ULTRON_LLM_MODE"] = mode_val
                mode_idx = i
                break
    if mode_idx is not None:
        sys.argv = sys.argv[:mode_idx] + sys.argv[mode_idx + 2:]

    # Check for --ir flag in CLI args
    ir_flag = {"--ir"}
    use_ir = any(arg in ir_flag for arg in sys.argv)
    if use_ir:
        os.environ["ULTRON_IR"] = "1"
        sys.argv = [arg for arg in sys.argv if arg not in ir_flag]

    banner()

    if len(sys.argv) > 1:
        arg = sys.argv[1]

        if arg in ("--help", "-h", "help"):
            show_help()
            sys.exit(0)

        if arg == "list":
            list_repos()
        elif arg == "config":
            cmd_config(sys.argv[2:])
        elif arg == "scan":
            if len(sys.argv) < 3:
                print(f"  {RED}[-]{RST} usage: ultron scan <repo-name>")
            else:
                cmd_scan(sys.argv[2])
        elif arg == "delete":
            if len(sys.argv) < 3:
                print(f"  {RED}[-]{RST} usage: ultron delete <repo-name> or ultron delete --all")
            else:
                cmd_delete(sys.argv[2:])
        elif arg in ("visualise", "visualize"):
            if len(sys.argv) < 3:
                print(f"  {RED}[-]{RST} usage: ultron visualise <repo-name>")
            else:
                cmd_visualise(sys.argv[2])
        else:
            cmd_clone(arg)

        sys.exit(0)

    interactive()

if __name__ == "__main__":
    main()
