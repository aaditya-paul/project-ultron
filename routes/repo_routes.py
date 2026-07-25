"""Repository management routes — clone, scan, list, delete, visualise.

Each function is a standalone callable that returns structured dicts,
making them directly usable as MCP tools without an HTTP layer.
"""

import os
import sys

from cloner import (
    CLONES_DIR, WORKSPACE_DIR,
    extract_repo_name, repo_path, repo_exists, get_remote_url,
    clone_repo as _clone_repo, list_repos as _list_repos,
    delete_repo as _delete_repo, delete_all_repos as _delete_all,
    pull_repo,
)
from detector import analyze_project, save_workspace_manifest
from parser import parse_repo, save_ast
from graph import load_ast, build_ir_dependency_graph, save_graph, render_graph, render_security_graph
from security_graph import build_node_index
from taint_graph import render_taint_graph
from rules import run_rules
from llm_detector import run_llm_detection, run_llm_auth_validation
from llm_client import load_config, create_llm_client, CLOUD_PROVIDER_NAMES
from routes.pipeline_routes import run_ir_pipeline as _run_ir_pipeline_internal


def list_repos():
    """List all cloned repositories.

    MCP tool candidate: ultron_list_repos

    Returns:
        dict with "repos" key containing list of repo names and status info
    """
    if not os.path.isdir(CLONES_DIR):
        return {"repos": [], "count": 0}

    entries = sorted(os.listdir(CLONES_DIR))
    repos = []
    for e in entries:
        path = os.path.join(CLONES_DIR, e, ".git")
        if os.path.isdir(path):
            ws_path = os.path.join(WORKSPACE_DIR, e)
            repos.append({
                "name": e,
                "path": repo_path(e),
                "has_workspace": os.path.isdir(ws_path),
                "has_ast": os.path.isfile(os.path.join(ws_path, "ast", "ast.json")) if os.path.isdir(ws_path) else False,
            })

    return {"repos": repos, "count": len(repos)}


def clone_repo(url, pull_if_exists=True):
    """Clone a repository and run full analysis.

    MCP tool candidate: ultron_clone_repo

    Args:
        url: Git repository URL
        pull_if_exists: If True and repo exists, pull latest before analyzing

    Returns:
        dict with result status and repo info
    """
    name = extract_repo_name(url)
    if repo_exists(name):
        if pull_if_exists:
            target_dir = repo_path(name)
            success = pull_repo(target_dir)
        return {
            "success": True,
            "repo_name": name,
            "cloned": False,
            "message": f"Repository '{name}' already exists locally",
        }

    result = _clone_repo(url)
    if not result:
        return {
            "success": False,
            "repo_name": name,
            "cloned": False,
            "error": "Clone operation failed",
        }

    analysis_result = _run_analysis_pipeline(url, name)
    return {
        "success": True,
        "repo_name": name,
        "cloned": True,
        "analysis": analysis_result,
    }


def scan_repo(name):
    """Re-analyze an already-cloned repository.

    MCP tool candidate: ultron_scan_repo

    Args:
        name: Repository name (must exist in clones/)

    Returns:
        dict with analysis results
    """
    if not repo_exists(name):
        return {
            "success": False,
            "error": f"Repository '{name}' not found in clones/. Clone it first.",
        }

    target = repo_path(name)
    remote_url = get_remote_url(name) or f"clones/{name}"
    analysis_result = _run_analysis_pipeline(remote_url, name)
    return {
        "success": True,
        "repo_name": name,
        "analysis": analysis_result,
    }


def get_repo_status(name):
    """Get detailed status of a cloned repository.

    MCP tool candidate: ultron_get_repo_status

    Args:
        name: Repository name

    Returns:
        dict with status information
    """
    if not repo_exists(name):
        return {"exists": False, "repo_name": name, "error": "Not found"}

    target = repo_path(name)
    ws = os.path.join(WORKSPACE_DIR, name)
    ast_path = os.path.join(ws, "ast", "ast.json")
    manifest_path = os.path.join(ws, "manifest.json")
    graph_dir = os.path.join(ws, "graph")

    return {
        "exists": True,
        "repo_name": name,
        "path": target,
        "remote_url": get_remote_url(name),
        "workspace": {
            "exists": os.path.isdir(ws),
            "has_ast": os.path.isfile(ast_path),
            "has_manifest": os.path.isfile(manifest_path),
            "has_graphs": os.path.isdir(graph_dir) and len(os.listdir(graph_dir)) > 0 if os.path.isdir(graph_dir) else False,
        },
        "graph_svgs": _list_graph_svgs(name),
    }


def delete_repo(name):
    """Delete a cloned repository and its workspace.

    MCP tool candidate: ultron_delete_repo

    Args:
        name: Repository name or "--all" to delete everything

    Returns:
        dict with deletion result
    """
    name_lower = name.lower()
    if name_lower == "--all":
        return delete_all_repos()

    if not repo_exists(name):
        return {"success": False, "error": f"Repository '{name}' not found."}

    from cloner import _rmtree as _rmtree_impl, delete_workspace
    _rmtree_impl(repo_path(name))
    delete_workspace(name)

    return {
        "success": True,
        "repo_name": name,
        "message": f"Repository '{name}' and its workspace deleted.",
    }


def delete_all_repos():
    """Delete all cloned repositories and workspaces.

    MCP tool candidate: ultron_delete_all_repos

    Returns:
        dict with deletion result
    """
    if not os.path.isdir(CLONES_DIR):
        return {"success": False, "error": "No clones directory found."}

    repos = [e for e in os.listdir(CLONES_DIR) if os.path.isdir(os.path.join(CLONES_DIR, e, ".git"))]
    if not repos:
        return {"success": False, "error": "No cloned repositories to delete."}

    from cloner import _rmtree as _rmtree_impl, delete_workspace
    deleted = []
    for r in repos:
        _rmtree_impl(os.path.join(CLONES_DIR, r))
        delete_workspace(r)
        deleted.append(r)

    return {
        "success": True,
        "deleted_count": len(deleted),
        "deleted_repos": deleted,
        "message": f"Deleted {len(deleted)} repositories.",
    }


def visualise_repo(name):
    """Regenerate visualizations (SVGs) from cached AST for a repository.

    MCP tool candidate: ultron_visualise_repo

    Args:
        name: Repository name

    Returns:
        dict with visualization file paths
    """
    ast_data = load_ast(WORKSPACE_DIR, name)
    if not ast_data:
        return {"success": False, "error": f"No AST data found for '{name}'. Run scan first."}

    target = repo_path(name)
    if not os.path.isdir(target):
        return {"success": False, "error": f"Repo directory not found at {target}"}

    ir_modules, cg, taint_paths = _run_ir_pipeline_internal(target, ast_data)
    if not ir_modules:
        return {"success": False, "error": "No IR modules extracted."}

    out_dir = os.path.join(WORKSPACE_DIR, name, "graph")
    os.makedirs(out_dir, exist_ok=True)

    from graph import build_ir_dependency_graph, save_graph, render_graph
    dep_graph = build_ir_dependency_graph(ir_modules, cg)
    save_graph(WORKSPACE_DIR, name, dep_graph)

    dep_svg = os.path.join(out_dir, "dependency_graph.svg")
    render_graph(dep_graph, dep_svg)

    taint_svg = os.path.join(out_dir, "taint_graph.svg")
    render_taint_graph(taint_paths, taint_svg)

    from security_graph import build_security_graph_from_ir
    security_graph = build_security_graph_from_ir(ir_modules, cg, taint_paths)

    sec_svg = os.path.join(out_dir, "security_graph.svg")
    render_security_graph(security_graph, sec_svg)

    return {
        "success": True,
        "repo_name": name,
        "visualizations": {
            "dependency_graph": dep_svg if os.path.isfile(dep_svg) else None,
            "taint_graph": taint_svg if os.path.isfile(taint_svg) else None,
            "security_graph": sec_svg if os.path.isfile(sec_svg) else None,
        },
    }


# ── Internal helpers ────────────────────────────────────────────────────────

def _run_analysis_pipeline(repo_url, repo_name):
    """Run the full detection → AST → IR → analysis pipeline.

    Returns a structured dict with all results, no console printing.
    """
    target = repo_path(repo_name)

    analysis = analyze_project(target)
    manifest = save_workspace_manifest(repo_name, repo_url, analysis)

    ast_data = parse_repo(target)
    ast_path = save_ast(WORKSPACE_DIR, repo_name, ast_data)

    ir_modules, cg, taint_paths = _run_ir_pipeline_internal(target, ast_data)

    config = load_config()
    mode = config.get("llm_mode", "local")
    use_llm = config.get("use_llm", True)

    from security_graph import build_security_graph_from_ir
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

    from graph import build_ir_dependency_graph, save_graph, render_graph
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

    node_index = build_node_index(ir_modules)

    return {
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


def _list_graph_svgs(repo_name):
    graph_dir = os.path.join(WORKSPACE_DIR, repo_name, "graph")
    if not os.path.isdir(graph_dir):
        return {}
    svgs = {}
    for name in ("dependency_graph.svg", "taint_graph.svg", "security_graph.svg"):
        path = os.path.join(graph_dir, name)
        if os.path.isfile(path):
            svgs[name] = path
    return svgs


import json
