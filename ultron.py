import sys
import os
import json

from colors import CYAN, RED, GRN, WHT, DIM, YLW, RST, BOLD
from banner import banner
from cloner import clone_repo, list_repos, delete_repo, delete_all_repos, repo_exists, repo_path, extract_repo_name, get_remote_url
from detector import analyze_project, show_detected_types, save_workspace_manifest, WORKSPACE_DIR
from parser import parse_repo, save_ast, show_parse_summary
from graph import load_ast, build_ir_dependency_graph, save_graph, render_graph, render_security_graph, show_graph_summary
from security_graph import build_security_graph_from_ir, show_security_graph_summary
from rules import show_findings, run_rules
from help import show_help
from llm_client import LocalLLMClient, CloudLLMClient, load_config, create_llm_client, CLOUD_PROVIDER_NAMES
from taint_graph import render_taint_graph
from llm_detector import run_llm_detection
from extractors.js_ts import JsTsExtractor
from extractors.resolver import SymbolResolver
from extractors.call_graph import CallGraph
from extractors.taint_engine import TaintEngine


def run_ir_pipeline(target: str, ast_data: dict):
    """Extract IR from JS/TS files, resolve symbols, build call graph, run taint engine.
    Returns (ir_modules, call_graph, taint_paths).
    """
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

    if not ir_modules:
        print(f"  {DIM}[*]{RST} IR pipeline: no JS/TS files to process")
        return ir_modules, CallGraph(), []

    resolver = SymbolResolver(ir_modules)
    resolver.resolve_all()
    total_resolved = sum(len(mod.call_resolutions) for mod in ir_modules)

    cg = CallGraph(ir_modules)
    te = TaintEngine(ir_modules, cg)
    taint_paths = te.run()

    print(f"  {GRN}[+]{RST} IR pipeline: {WHT}{len(ir_modules)}{RST} files, {WHT}{total_ir_funcs}{RST} functions, {WHT}{total_resolved}{RST} call resolutions, {WHT}{len(taint_paths)}{RST} taint paths")

    if taint_paths:
        sanitized = [p for p in taint_paths if p.sanitized]
        unsanitized = [p for p in taint_paths if not p.sanitized]
        if unsanitized:
            print(f"  {RED}[!]{RST} {WHT}{len(unsanitized)}{RST} unsanitized taint paths detected:")
            for p in unsanitized[:5]:
                print(f"       {p.source_tag} -> {p.sink_target} ({p.sink_type}) [{p.file_path}]")
        if sanitized:
            print(f"  {GRN}[+]{RST} {WHT}{len(sanitized)}{RST} sanitized taint paths (VALIDATION_GATE)")

    return ir_modules, cg, taint_paths


def print_terminal_taint(security_graph):
    print(f"\n  {CYAN}{BOLD}TAINT PROPAGATION PATHS (TERMINAL VIEW){RST}")
    print(f"  {DIM}──────────────────────────────────────────────────{RST}")

    flows = security_graph.get("flows", [])
    if not flows:
        print(f"    {DIM}No taint propagation flows detected.{RST}")
    else:
        for idx, flow in enumerate(flows):
            print(f"    {BOLD}Path #{idx+1}: {flow['source']} --> {flow['sink_type']}{RST}")
            labels = flow.get("path_labels", [])
            for step_idx, step in enumerate(labels):
                if step_idx == 0:
                    print(f"      {RED}[SOURCE] {step}{RST}")
                elif step_idx == len(labels) - 1:
                    print(f"      --> {RED}[SINK] {step}{RST}")
                else:
                    print(f"      --> {YLW}{step}{RST}")

            san_status = f"{GRN}SANITIZED (via {', '.join(flow['validators'])}){RST}" if flow["validated"] else f"{RED}UNSANITIZED{RST}"
            print(f"      {BOLD}Status:{RST} {san_status}\n")
    print(f"  {DIM}──────────────────────────────────────────────────{RST}\n")


def run_ir_analysis(repo_name, target, ir_modules, call_graph, taint_paths):
    """Build security graph from IR, run rules + LLM detector, save results, generate visualizations."""
    out_dir = os.path.join(WORKSPACE_DIR, repo_name, "graph")
    os.makedirs(out_dir, exist_ok=True)

    config = load_config()
    mode = os.environ.get("ULTRON_LLM_MODE") or config.get("llm_mode", "local")

    print(f"  {CYAN}[*]{RST} building security graph from IR data...")
    security_graph = build_security_graph_from_ir(ir_modules, call_graph, taint_paths)

    print(f"  {CYAN}[*]{RST} running deterministic rules...")
    findings = list(run_rules(security_graph))
    show_findings(findings)
    print_terminal_taint(security_graph)

    print(f"  {CYAN}[*]{RST} generating dependency graph...")
    dep_graph = build_ir_dependency_graph(ir_modules, call_graph)
    gpath = save_graph(WORKSPACE_DIR, repo_name, dep_graph)
    show_graph_summary(dep_graph)
    if gpath:
        print(f"  {DIM}[*]{RST} DOT file saved -> {WHT}{gpath}{RST}")

    dep_out = os.path.join(out_dir, "dependency_graph.svg")
    dep_vis = render_graph(dep_graph, dep_out)
    if dep_vis:
        print(f"  {GRN}[+]{RST} dependency visualisation saved -> {WHT}{dep_vis}{RST}")

    if taint_paths:
        taint_out = os.path.join(out_dir, "taint_graph.svg")
        taint_vis = render_taint_graph(taint_paths, taint_out)
        if taint_vis:
            print(f"  {GRN}[+]{RST} taint propagation visualisation saved -> {WHT}{taint_vis}{RST}")

    # --- LLM initialization + detector (can be slow) ---
    use_llm = os.environ.get("ULTRON_NO_LLM") != "1"
    detector_client = None

    if use_llm:
        print(f"  {CYAN}[*]{RST} initializing {mode} LLM client for vulnerability detection...")
        if mode == "cloud":
            if create_llm_client(part="detector").is_available():
                detector_client = create_llm_client(part="detector")
                chain = detector_client._get_chain()
                providers = ", ".join(CLOUD_PROVIDER_NAMES.get(p, p) for p in chain)
                print(f"  {GRN}[+]{RST} cloud providers configured: {WHT}{providers}{RST} (model: {detector_client.model})")
            else:
                print(f"  {YLW}[!]{RST} no API keys configured for detector — using deterministic rules")
        else:
            if create_llm_client(part="detector").is_available():
                detector_client = create_llm_client(part="detector")
                if detector_client._detect_api() == "ollama" and not detector_client.is_model_available():
                    print(f"  {YLW}[!]{RST} Ollama server active, but detector model {WHT}'{detector_client.model}'{RST} is not pulled.")
                    print(f"      To pull it, run: {GRN}ollama pull {detector_client.model}{RST}")
                    print(f"      Using deterministic flow rules (fallback).")
                    detector_client = None
                else:
                    print(f"  {GRN}[+]{RST} local LLM server active for vulnerability detection: {WHT}{detector_client.base_url}{RST} (model: {detector_client.model})")
            else:
                print(f"  {YLW}[!]{RST} no LLM available — running deterministic rules only")
    else:
        print(f"  {DIM}[*]{RST} LLM detection disabled (use_llm=false or --no-llm)")

    if detector_client and detector_client.is_available():
        llm_findings = run_llm_detection(repo_name, security_graph, detector_client, verbose=False)
        findings.extend(llm_findings)
        show_findings(llm_findings)

    spath = os.path.join(out_dir, "security_graph.json")
    with open(spath, "w", encoding="utf-8") as f:
        json.dump({
            "security_graph": security_graph,
            "findings": findings,
        }, f, indent=2, ensure_ascii=False)
    print(f"  {DIM}[*]{RST} security graph saved -> {WHT}{spath}{RST}")
    show_security_graph_summary(security_graph)

    # Security graph SVG (always generated, path always shown)
    sec_out = os.path.join(out_dir, "security_graph.svg")
    sec_vis = render_security_graph(security_graph, sec_out)
    if sec_vis:
        print(f"  {GRN}[+]{RST} security graph visualisation saved -> {WHT}{sec_vis}{RST}")

    # If visualise flag is on, open SVGs in browser
    if config.get("visualise", False) or os.environ.get("ULTRON_VISUALISE") == "1":
        import webbrowser
        for svg_name in ["dependency_graph.svg", "taint_graph.svg", "security_graph.svg"]:
            svg_path = os.path.join(out_dir, svg_name)
            if os.path.isfile(svg_path):
                try:
                    webbrowser.open(f"file://{os.path.abspath(svg_path)}")
                except Exception:
                    pass


def save_and_report(repo_name, target, ast_data, ir_modules, call_graph, taint_paths):
    ast_path = save_ast(WORKSPACE_DIR, repo_name, ast_data)
    if ast_path:
        show_parse_summary(repo_name, ast_data)
        print(f"  {DIM}[*]{RST} AST saved -> {WHT}{ast_path}{RST}")
        print()
        run_ir_analysis(repo_name, target, ir_modules, call_graph, taint_paths)


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

    print(f"  {CYAN}[*]{RST} running IR pipeline...")
    ir_modules, cg, taint_paths = run_ir_pipeline(target, ast_data)

    save_and_report(repo_name, target, ast_data, ir_modules, cg, taint_paths)


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

    print(f"  {CYAN}[*]{RST} running IR pipeline...")
    ir_modules, cg, taint_paths = run_ir_pipeline(target, ast_data)

    save_and_report(name, target, ast_data, ir_modules, cg, taint_paths)


def cmd_visualise(name):
    ast_data = load_ast(WORKSPACE_DIR, name)
    if not ast_data:
        print(f"  {YLW}[!]{RST} no AST data found. run scan first.")
        return
    target = repo_path(name)
    if not os.path.isdir(target):
        print(f"  {RED}[-]{RST} repo directory not found at {WHT}{target}{RST}")
        return

    print(f"  {CYAN}[*]{RST} re-extracting IR from source files...")
    ir_modules, cg, taint_paths = run_ir_pipeline(target, ast_data)

    if not ir_modules:
        print(f"  {YLW}[!]{RST} no IR modules extracted.")
        return

    out_dir = os.path.join(WORKSPACE_DIR, name, "graph")
    os.makedirs(out_dir, exist_ok=True)

    print(f"  {CYAN}[*]{RST} building dependency graph...")
    dep_graph = build_ir_dependency_graph(ir_modules, cg)
    gpath = save_graph(WORKSPACE_DIR, name, dep_graph)
    show_graph_summary(dep_graph)
    if gpath:
        print(f"  {DIM}[*]{RST} graph saved -> {WHT}{gpath}{RST}")

    dep_out = os.path.join(out_dir, "dependency_graph.svg")
    dep_vis = render_graph(dep_graph, dep_out)
    if dep_vis:
        print(f"  {GRN}[+]{RST} dependency visualisation saved -> {WHT}{dep_vis}{RST}")

    print()
    run_ir_analysis(name, target, ir_modules, cg, taint_paths)


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
        print(f"\n  {CYAN}{BOLD}ULTRON CONFIGURATION{RST}")
        print(f"  {DIM}──────────────────────────────────────────────────{RST}")
        print(f"    {BOLD}llm_mode{RST}     : {WHT}{config.get('llm_mode', 'local')}{RST}")
        print(f"    {BOLD}llm_url{RST}      : {WHT}{config.get('llm_url')}{RST}")
        print(f"    {BOLD}llm_model{RST}    : {WHT}{config.get('llm_model')}{RST}")
        print(f"    {BOLD}temperature{RST}  : {WHT}{config.get('temperature')}{RST}")
        print(f"    {BOLD}max_tokens{RST}   : {WHT}{config.get('max_tokens')}{RST}")
        print(f"    {BOLD}timeout{RST}      : {WHT}{config.get('timeout')}{RST}")
        print(f"    {BOLD}num_workers{RST}   : {WHT}{config.get('num_workers')}{RST}")
        print(f"    {BOLD}version{RST}       : {WHT}{config.get('version')}{RST}")
        print(f"    {BOLD}verbose{RST}      : {WHT}{config.get('verbose', False)}{RST}")
        print(f"    {BOLD}visualise{RST}   : {WHT}{config.get('visualise', False)}{RST}")
        print(f"    {BOLD}use_llm{RST}      : {WHT}{config.get('use_llm', True)}{RST}")
        print(f"    {BOLD}enable_cache{RST} : {WHT}{config.get('enable_cache', True)}{RST}")
        print(f"    {BOLD}cache_only{RST}   : {WHT}{config.get('cache_only', False)}{RST}")

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
            rate_limits = config.get("rate_limits", {})
            if rate_limits:
                print(f"\n  {CYAN}{BOLD}RATE LIMITS{RST}")
                print(f"  {DIM}──────────────────────────────────────────────────{RST}")
                for prov, limits in rate_limits.items():
                    rpm = limits.get("requests_per_minute", "?")
                    concur = limits.get("max_concurrent", "?")
                    print(f"    {BOLD}{prov:<12}{RST} : {WHT}{rpm}{RST} req/min, {WHT}{concur}{RST} concurrent")

        print(f"\n  {CYAN}{BOLD}SPECIFIC LLM PARTS OVERRIDES{RST}")
        print(f"  {DIM}──────────────────────────────────────────────────{RST}")
        overrides = config.get("model_overrides", {})
        if overrides:
            for part, model in overrides.items():
                print(f"    {BOLD}{part:<12}{RST} : {WHT}{model}{RST}")
        else:
            print(f"    {DIM}none set{RST}")

        print(f"\n  {DIM}To change a model override, run: {GRN}config <part> <model-name>{RST}")
        print(f"  {DIM}To change a setting, run: {GRN}config <setting> <value>{RST}")
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
            "llm_mode": "local",
            "visualise": False,
            "use_llm": True,
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
        print(f"  {RED}[-]{RST} usage: config <part/setting> <value> (e.g. config classifier llama3.1:8b)")
        return

    part = args[0].lower()
    val_str = args[1]

    valid_parts = {"classifier", "detector", "exploiter", "reporter", "default"}
    valid_settings = {"verbose", "visualise", "temperature", "max_tokens", "timeout", "num_workers", "llm_url", "llm_mode", "use_llm"}

    if part not in valid_parts and part not in valid_settings:
        print(f"  {RED}[-]{RST} invalid part or setting '{part}'. Valid parts: {', '.join(valid_parts)}, Settings: {', '.join(valid_settings)}")
        return

    if part in valid_settings:
        if part == "verbose":
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
        elif part == "visualise":
            val = val_str.lower() in ("true", "1", "yes", "on", "enable", "enabled")
            config["visualise"] = val
            print(f"  {GRN}[+]{RST} setting {BOLD}visualise{RST} updated to {WHT}{val}{RST}")
        elif part == "use_llm":
            val = val_str.lower() in ("true", "1", "yes", "on", "enable", "enabled")
            config["use_llm"] = val
            print(f"  {GRN}[+]{RST} setting {BOLD}use_llm{RST} updated to {WHT}{val}{RST}")
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

        debug_flags = {"--debug", "-d", "--verbose", "-v"}
        cmd_debug = any(p in debug_flags for p in parts)
        if cmd_debug:
            os.environ["ULTRON_DEBUG"] = "1"
            print(f"  {CYAN}[*]{RST} Debug/Verbose mode enabled for this command")
            parts = [p for p in parts if p not in debug_flags]
            line = " ".join(parts)
            cmd = parts[0].lower() if parts else ""
        elif "ULTRON_DEBUG" in os.environ:
            del os.environ["ULTRON_DEBUG"]

        vis_flags = {"--visualise", "--visualize"}
        cmd_vis = any(p in vis_flags for p in parts)
        if cmd_vis:
            os.environ["ULTRON_VISUALISE"] = "1"
            print(f"  {CYAN}[*]{RST} Terminal visualisation enabled for this command")
            parts = [p for p in parts if p not in vis_flags]
            line = " ".join(parts)
            cmd = parts[0].lower() if parts else ""
        elif "ULTRON_VISUALISE" in os.environ:
            del os.environ["ULTRON_VISUALISE"]

        no_llm_flags = {"--no-llm"}
        cmd_no_llm = any(p in no_llm_flags for p in parts)
        if cmd_no_llm:
            os.environ["ULTRON_NO_LLM"] = "1"
            print(f"  {CYAN}[*]{RST} LLM detection disabled for this command")
            parts = [p for p in parts if p not in no_llm_flags]
            line = " ".join(parts)
            cmd = parts[0].lower() if parts else ""
        elif "ULTRON_NO_LLM" in os.environ:
            del os.environ["ULTRON_NO_LLM"]

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
    config = load_config()
    if config.get("verbose", False):
        os.environ["ULTRON_GLOBAL_DEBUG"] = "1"
        os.environ["ULTRON_DEBUG"] = "1"
    if config.get("visualise", False):
        os.environ["ULTRON_VISUALISE"] = "1"
    if not config.get("use_llm", True):
        os.environ["ULTRON_NO_LLM"] = "1"

    no_llm_flags = {"--no-llm"}
    if any(arg in sys.argv for arg in no_llm_flags):
        os.environ["ULTRON_NO_LLM"] = "1"
        sys.argv = [arg for arg in sys.argv if arg not in no_llm_flags]

    debug_flags = {"--debug", "-d", "--verbose", "-v"}
    if any(arg in sys.argv for arg in debug_flags):
        os.environ["ULTRON_GLOBAL_DEBUG"] = "1"
        os.environ["ULTRON_DEBUG"] = "1"
        sys.argv = [arg for arg in sys.argv if arg not in debug_flags]

    vis_flags = {"--visualise", "--visualize"}
    if any(arg in sys.argv for arg in vis_flags):
        os.environ["ULTRON_VISUALISE"] = "1"
        sys.argv = [arg for arg in sys.argv if arg not in vis_flags]

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

    banner()

    valid_cmds = {"list", "scan", "config", "delete", "visualise", "visualize", "--help", "-h", "help"}
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg.startswith("--") and arg not in valid_cmds:
            print(f"  {RED}[-]{RST} unknown flag: {WHT}{arg}{RST}")
            sys.exit(1)
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
