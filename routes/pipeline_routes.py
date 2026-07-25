"""Analysis pipeline routes — detection, AST, IR, taint, rules, LLM.

Each function is a standalone callable that returns structured dicts,
making them directly usable as MCP tools without an HTTP layer.
"""

import os
import json

from cloner import WORKSPACE_DIR, repo_path, repo_exists, get_remote_url
from detector import analyze_project, save_workspace_manifest
from parser import parse_repo, save_ast, show_parse_summary
from graph import load_ast, build_ir_dependency_graph, save_graph, render_graph, render_security_graph
from security_graph import build_security_graph_from_ir, build_node_index, show_security_graph_summary
from taint_graph import render_taint_graph
from rules import run_rules
from llm_client import load_config, create_llm_client, CLOUD_PROVIDER_NAMES
from llm_detector import run_llm_detection, run_llm_auth_validation
from extractors.js_ts import JsTsExtractor
from extractors.resolver import SymbolResolver
from extractors.call_graph import CallGraph
from extractors.taint_engine import TaintEngine


def _print(msg):
    """Silent print — no-op for route context. Override to capture."""
    pass


def run_detection(repo_name):
    """Detect languages and frameworks in a cloned repository.

    MCP tool candidate: ultron_run_detection

    Args:
        repo_name: Name of cloned repository

    Returns:
        dict with detected languages and frameworks
    """
    target = repo_path(repo_name)
    if not os.path.isdir(target):
        return {"success": False, "error": f"Repository '{repo_name}' not found."}

    analysis = analyze_project(target)
    save_workspace_manifest(repo_name, get_remote_url(repo_name) or f"clones/{repo_name}", analysis)

    return {
        "success": True,
        "repo_name": repo_name,
        "languages": analysis.get("languages", []),
        "frameworks": analysis.get("frameworks", []),
    }


def run_ast_parse(repo_name):
    """Parse AST for a cloned repository.

    MCP tool candidate: ultron_run_ast_parse

    Args:
        repo_name: Name of cloned repository

    Returns:
        dict with AST parse results
    """
    target = repo_path(repo_name)
    if not os.path.isdir(target):
        return {"success": False, "error": f"Repository '{repo_name}' not found."}

    ast_data = parse_repo(target)
    ast_path = save_ast(WORKSPACE_DIR, repo_name, ast_data)

    file_count = len(ast_data.get("files", {}))
    total = sum(
        len(info.get("functions", [])) + len(info.get("classes", []))
        for info in ast_data.get("files", {}).values()
    )

    return {
        "success": True,
        "repo_name": repo_name,
        "ast_path": ast_path,
        "total_files": file_count,
        "total_functions_and_classes": total,
        "files_by_language": _count_by_language(ast_data),
    }


def run_ir_pipeline(target, ast_data):
    """Extract IR from JS/TS files, resolve symbols, build call graph, run taint engine.

    This is the same logic as ultron.py:run_ir_pipeline but returns structured data.

    MCP tool candidate: ultron_run_ir_pipeline

    Args:
        target: Path to the cloned repository
        ast_data: AST data dict from parse_repo()

    Returns:
        tuple of (ir_modules, call_graph, taint_paths)
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
        return ir_modules, CallGraph(), []

    resolver = SymbolResolver(ir_modules)
    resolver.resolve_all()
    total_resolved = sum(len(mod.call_resolutions) for mod in ir_modules)

    cg = CallGraph(ir_modules)
    te = TaintEngine(ir_modules, cg)
    taint_paths = te.run()

    return ir_modules, cg, taint_paths


def run_rules_pipeline(repo_name):
    """Run deterministic security rules on a repository.

    MCP tool candidate: ultron_run_rules

    Args:
        repo_name: Name of cloned repository

    Returns:
        dict with rule findings
    """
    target = repo_path(repo_name)
    if not os.path.isdir(target):
        return {"success": False, "error": f"Repository '{repo_name}' not found."}

    ast_data = load_ast(WORKSPACE_DIR, repo_name)
    if not ast_data:
        return {"success": False, "error": f"No AST data for '{repo_name}'. Run scan first."}

    ir_modules, cg, taint_paths = run_ir_pipeline(target, ast_data)
    security_graph = build_security_graph_from_ir(ir_modules, cg, taint_paths)

    findings = list(run_rules(security_graph))

    return {
        "success": True,
        "repo_name": repo_name,
        "findings": findings,
        "findings_count": len(findings),
        "by_severity": {
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
        },
    }


def run_llm_detection_pipeline(repo_name):
    """Run LLM-based vulnerability detection on a repository.

    MCP tool candidate: ultron_run_llm_detection

    Args:
        repo_name: Name of cloned repository

    Returns:
        dict with LLM findings
    """
    target = repo_path(repo_name)
    if not os.path.isdir(target):
        return {"success": False, "error": f"Repository '{repo_name}' not found."}

    ast_data = load_ast(WORKSPACE_DIR, repo_name)
    if not ast_data:
        return {"success": False, "error": f"No AST data for '{repo_name}'. Run scan first."}

    detector_client = create_llm_client(part="detector")
    if not detector_client or not detector_client.is_available():
        return {"success": False, "error": "No LLM client available. Check configuration."}

    ir_modules, cg, taint_paths = run_ir_pipeline(target, ast_data)
    security_graph = build_security_graph_from_ir(ir_modules, cg, taint_paths)

    llm_findings = run_llm_detection(repo_name, security_graph, detector_client, ir_modules=ir_modules, verbose=False)

    return {
        "success": True,
        "repo_name": repo_name,
        "llm_findings": llm_findings,
        "llm_findings_count": len(llm_findings),
    }


def run_full_analysis(repo_name):
    """Run the complete analysis pipeline: detection, AST, IR, taint, rules, and LLM.

    MCP tool candidate: ultron_run_full_analysis

    Args:
        repo_name: Name of cloned repository

    Returns:
        dict with complete analysis results
    """
    target = repo_path(repo_name)
    if not os.path.isdir(target):
        return {"success": False, "error": f"Repository '{repo_name}' not found."}

    remote_url = get_remote_url(repo_name) or f"clones/{repo_name}"
    analysis = analyze_project(target)
    manifest = save_workspace_manifest(repo_name, remote_url, analysis)

    ast_data = parse_repo(target)
    ast_path = save_ast(WORKSPACE_DIR, repo_name, ast_data)

    ir_modules, cg, taint_paths = run_ir_pipeline(target, ast_data)

    config = load_config()
    mode = config.get("llm_mode", "local")
    use_llm = config.get("use_llm", True)

    security_graph = build_security_graph_from_ir(ir_modules, cg, taint_paths)

    findings = list(run_rules(security_graph))

    detector_client = None
    auth_validated = None
    llm_findings = []

    if use_llm:
        client = create_llm_client(part="detector")
        if client and client.is_available():
            detector_client = client
            flow_rules = {"unvalidated-source-to-sink", "sql-injection-via-concat",
                           "path-traversal", "ssrf-dynamic-url", "database-write-without-validation"}
            findings = [f for f in findings if f.get("rule") not in flow_rules]
            auth_validated = run_llm_auth_validation(security_graph, detector_client)
            findings = [f for f in findings if (
                f.get("rule") != "missing-authentication" or
                f.get("route", "") in (auth_validated or {})
            )]
            llm_findings = run_llm_detection(repo_name, security_graph, detector_client, ir_modules=ir_modules, verbose=False)
            findings.extend(llm_findings)

    dep_graph = build_ir_dependency_graph(ir_modules, cg)
    gpath = save_graph(WORKSPACE_DIR, repo_name, dep_graph)

    out_dir = os.path.join(WORKSPACE_DIR, repo_name, "graph")
    os.makedirs(out_dir, exist_ok=True)

    dep_svg = os.path.join(out_dir, "dependency_graph.svg")
    render_graph(dep_graph, dep_svg)

    taint_svg = os.path.join(out_dir, "taint_graph.svg")
    if taint_paths:
        render_taint_graph(taint_paths, taint_svg)

    sec_svg = os.path.join(out_dir, "security_graph.svg")
    render_security_graph(security_graph, sec_svg)

    spath = os.path.join(out_dir, "security_graph.json")
    with open(spath, "w", encoding="utf-8") as f:
        json.dump({"security_graph": security_graph, "findings": findings}, f, indent=2, ensure_ascii=False)

    return {
        "success": True,
        "repo_name": repo_name,
        "languages": analysis.get("languages", []),
        "frameworks": analysis.get("frameworks", []),
        "manifest": manifest,
        "ast_path": ast_path,
        "ast_file_count": len(ast_data.get("files", {})),
        "ir_modules": len(ir_modules),
        "taint_paths": len(taint_paths),
        "findings_count": len(findings),
        "findings": findings,
        "security_graph": {
            "flows": len(security_graph.get("flows", [])),
            "unvalidated_flows": security_graph.get("summary", {}).get("unvalidated_flows", 0),
            "routes": security_graph.get("summary", {}).get("total_routes", 0),
            "protected_routes": security_graph.get("subgraphs", {}).get("auth", {}).get("protected_count", 0),
            "unprotected_routes": security_graph.get("subgraphs", {}).get("auth", {}).get("unprotected_count", 0),
        },
        "visualizations": {
            "dependency_graph": dep_svg if os.path.isfile(dep_svg) else None,
            "taint_graph": taint_svg if os.path.isfile(taint_svg) else None,
            "security_graph": sec_svg if os.path.isfile(sec_svg) else None,
            "security_graph_json": spath,
        },
        "llm_used": detector_client is not None and detector_client.is_available(),
        "llm_mode": mode,
    }


def get_findings(repo_name):
    """Get cached findings from a previous scan.

    MCP tool candidate: ultron_get_findings

    Args:
        repo_name: Name of cloned repository

    Returns:
        dict with cached findings
    """
    spath = os.path.join(WORKSPACE_DIR, repo_name, "graph", "security_graph.json")
    if not os.path.isfile(spath):
        return {"success": False, "error": f"No cached findings for '{repo_name}'. Run scan first."}

    with open(spath, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "success": True,
        "repo_name": repo_name,
        "findings": data.get("findings", []),
        "findings_count": len(data.get("findings", [])),
    }


def get_security_graph(repo_name):
    """Get cached security graph data from a previous scan.

    MCP tool candidate: ultron_get_security_graph

    Args:
        repo_name: Name of cloned repository

    Returns:
        dict with cached security graph
    """
    spath = os.path.join(WORKSPACE_DIR, repo_name, "graph", "security_graph.json")
    if not os.path.isfile(spath):
        return {"success": False, "error": f"No cached security graph for '{repo_name}'. Run scan first."}

    with open(spath, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "success": True,
        "repo_name": repo_name,
        "security_graph": data.get("security_graph", {}),
    }


# ── Internal helpers ────────────────────────────────────────────────────────

def _count_by_language(ast_data):
    counts = {}
    for fpath, info in ast_data.get("files", {}).items():
        lang = info.get("language", "unknown")
        if lang not in counts:
            counts[lang] = {"files": 0, "functions": 0, "classes": 0}
        counts[lang]["files"] += 1
        counts[lang]["functions"] += len(info.get("functions", []))
        counts[lang]["classes"] += len(info.get("classes", []))
    return counts
