"""
Ultron Model Context Protocol (MCP) Server (ultron_mcp_server.py)
Exposes Ultron static analysis, LLM remediation, and Git DevEx integration as stdio MCP tools.
"""

import os
import sys
import json
import subprocess
from mcp.server.fastmcp import FastMCP

# ── Robust SSE Transport & Lifespan Initialization Patch ───────────────────
try:
    from mcp.server.session import ServerSession, InitializationState
    _orig_received_request = ServerSession._received_request
    _orig_received_notification = ServerSession._received_notification

    async def _patched_received_request(self, responder):
        if self._initialization_state != InitializationState.Initialized:
            self._initialization_state = InitializationState.Initialized
        return await _orig_received_request(self, responder)

    async def _patched_received_notification(self, notification):
        if self._initialization_state != InitializationState.Initialized:
            self._initialization_state = InitializationState.Initialized
        try:
            return await _orig_received_notification(self, notification)
        except Exception:
            pass

    ServerSession._received_request = _patched_received_request
    ServerSession._received_notification = _patched_received_notification
except Exception:
    pass

from parser import parse_repo
from ultron import run_ir_pipeline
from security_graph import build_security_graph_from_ir
from rules import run_rules
from auto_fixer import UltronAutoFixer
from llm_client import create_llm_client
from llm_detector import run_llm_detection, run_llm_auth_validation

mcp = FastMCP("Ultron Security Engine")


def _audit_codebase(abs_path: str, verbose: bool = False):
    """Run IR static taint pipeline and LLM vulnerability detection (when LLM active)."""
    ast_data = parse_repo(abs_path)
    if not ast_data:
        return None, None, None, [], False

    ir_modules, cg, taint_paths = run_ir_pipeline(abs_path, ast_data, verbose=verbose)
    security_graph = build_security_graph_from_ir(ir_modules, cg, taint_paths)
    findings = list(run_rules(security_graph))

    detector_client = create_llm_client(part="detector")
    llm_active = False
    if detector_client and detector_client.is_available():
        llm_active = True
        repo_name = os.path.basename(abs_path) or "local"
        flow_rules = {"unvalidated-source-to-sink", "sql-injection-via-concat",
                       "path-traversal", "ssrf-dynamic-url", "database-write-without-validation"}
        findings = [f for f in findings if f.get("rule") not in flow_rules]
        auth_validated = run_llm_auth_validation(security_graph, detector_client)
        findings = [f for f in findings if (
            f.get("rule") != "missing-authentication" or
            f.get("route", "") in (auth_validated or {})
        )]
        llm_findings = run_llm_detection(repo_name, security_graph, detector_client, ir_modules=ir_modules, verbose=verbose)
        findings.extend(llm_findings)

    return security_graph, ir_modules, detector_client, findings, llm_active


@mcp.tool()
def ultron_scan(target_dir: str = ".") -> str:
    """Run full Ultron security audit (Static IR Taint Analysis + LLM Vulnerability Verification Agent) on a codebase directory."""
    abs_path = os.path.abspath(target_dir)
    if not os.path.isdir(abs_path):
        return json.dumps({"error": f"Directory not found: {target_dir}"})

    security_graph, ir_modules, detector_client, findings, llm_active = _audit_codebase(abs_path)
    if security_graph is None:
        return json.dumps({"error": "Failed to parse repository AST"})

    summary = {
        "target_directory": abs_path,
        "llm_detection_active": llm_active,
        "llm_model": detector_client.model if llm_active and detector_client else "None (Static Rules Only)",
        "total_vulnerabilities": len(findings),
        "high_severity": sum(1 for f in findings if f.get("severity") == "high"),
        "medium_severity": sum(1 for f in findings if f.get("severity") == "medium"),
        "low_severity": sum(1 for f in findings if f.get("severity") == "low"),
        "findings": findings
    }
    return json.dumps(summary, indent=2)


@mcp.tool()
def ultron_auto_fix(target_dir: str = ".") -> str:
    """Run Ultron security scan and invoke LLM Refactoring Agents to auto-patch vulnerable files using report context."""
    abs_path = os.path.abspath(target_dir)
    if not os.path.isdir(abs_path):
        return json.dumps({"error": f"Directory not found: {target_dir}"})

    security_graph, ir_modules, detector_client, findings, llm_active = _audit_codebase(abs_path)
    if security_graph is None:
        return json.dumps({"error": "Failed to parse repository AST"})

    fixer = UltronAutoFixer(abs_path, llm_client=detector_client)
    fix_results = fixer.apply_fixes(findings)

    summary = {
        "target_directory": abs_path,
        "llm_refactoring_agent": detector_client.model if detector_client and detector_client.is_available() else "AST Regex Fallback",
        "total_findings": len(findings),
        "remediation_attempts": fix_results
    }
    return json.dumps(summary, indent=2)


@mcp.tool()
def ultron_install_git_hook(target_dir: str = ".", auto_fix: bool = True) -> str:
    """Install project-specific Git pre-commit security hook in the target codebase directory.
    When installed, Git automatically runs Ultron security verification and LLM auto-fixing before every commit.
    """
    from ultron import install_git_hook
    ok, message = install_git_hook(target_dir, auto_fix=auto_fix)
    return json.dumps({
        "success": ok,
        "message": message,
        "target_directory": os.path.abspath(target_dir),
        "auto_fix_enabled": auto_fix
    }, indent=2)


@mcp.tool()
def ultron_remove_git_hook(target_dir: str = ".") -> str:
    """Uninstall/remove the project-specific Git pre-commit security hook from the target codebase directory."""
    from ultron import uninstall_git_hook
    ok, message = uninstall_git_hook(target_dir)
    return json.dumps({
        "success": ok,
        "message": message,
        "target_directory": os.path.abspath(target_dir)
    }, indent=2)


@mcp.tool()
def ultron_check_diff(target_dir: str = ".") -> str:
    """Run incremental delta security audit (Static IR + LLM Agent) on modified/uncommitted git diff files in the target codebase."""
    abs_path = os.path.abspath(target_dir)
    if not os.path.isdir(abs_path):
        return json.dumps({"error": f"Directory not found: {target_dir}"})

    try:
        res = subprocess.run(["git", "diff", "--name-only"], cwd=abs_path, capture_output=True, text=True)
        changed_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
    except Exception:
        changed_files = []

    security_graph, ir_modules, detector_client, all_findings, llm_active = _audit_codebase(abs_path)
    if security_graph is None:
        return json.dumps({"error": "Failed to parse repository AST"})

    diff_findings = [
        f for f in all_findings
        if not changed_files or any(cf in (f.get("file") or "").replace("\\", "/") for cf in changed_files)
    ]

    return json.dumps({
        "target_directory": abs_path,
        "llm_detection_active": llm_active,
        "changed_files_count": len(changed_files),
        "changed_files": changed_files,
        "total_diff_findings": len(diff_findings),
        "findings": diff_findings
    }, indent=2)


@mcp.tool()
def ultron_get_report(target_dir: str = ".") -> str:
    """Generate and return a full Markdown Security Analysis Report (Static IR + LLM Verification) with taint paths and SVG file locations."""
    abs_path = os.path.abspath(target_dir)
    if not os.path.isdir(abs_path):
        return json.dumps({"error": f"Directory not found: {target_dir}"})

    security_graph, ir_modules, detector_client, findings, llm_active = _audit_codebase(abs_path)
    if security_graph is None:
        return json.dumps({"error": "Failed to parse repository AST"})

    repo_name = os.path.basename(abs_path) or "local_repo"
    graph_dir = os.path.join(os.path.dirname(__file__), "workspace", repo_name, "graph")
    
    svg_files = {
        "security_graph_svg": os.path.join(graph_dir, "security_graph.svg") if os.path.isfile(os.path.join(graph_dir, "security_graph.svg")) else None,
        "taint_graph_svg": os.path.join(graph_dir, "taint_graph.svg") if os.path.isfile(os.path.join(graph_dir, "taint_graph.svg")) else None,
        "dependency_graph_svg": os.path.join(graph_dir, "dependency_graph.svg") if os.path.isfile(os.path.join(graph_dir, "dependency_graph.svg")) else None,
        "pdf_report": os.path.join(graph_dir, "security_report.pdf") if os.path.isfile(os.path.join(graph_dir, "security_report.pdf")) else None,
    }

    report_lines = [
        f"# ULTRON Security Analysis Report",
        f"**Target Directory**: `{abs_path}`",
        f"**LLM Vulnerability Verification**: `{'ACTIVE (' + detector_client.model + ')' if llm_active and detector_client else 'Disabled (Deterministic Rules Only)'}`",
        f"**Total Findings**: {len(findings)} (High: {sum(1 for f in findings if f.get('severity')=='high')}, Medium: {sum(1 for f in findings if f.get('severity')=='medium')}, Low: {sum(1 for f in findings if f.get('severity')=='low')})",
        "",
        "## Subgraph Architecture Summary",
        f"- **Authentication Subgraph**: {security_graph.get('subgraphs',{}).get('auth',{}).get('unprotected_count', 0)} unprotected API route(s) identified.",
        f"- **Database Subgraph**: {security_graph.get('subgraphs',{}).get('database',{}).get('total', 0)} database operation(s) tracked.",
        f"- **Network Subgraph**: {security_graph.get('subgraphs',{}).get('network',{}).get('total', 0)} external network call site(s) tracked.",
        "",
        "## Detailed Vulnerability Findings",
    ]

    for idx, f in enumerate(findings, 1):
        rule = f.get("rule") or f.get("rule_name") or "vulnerability"
        sev = f.get("severity", "high").upper()
        desc = f.get("description", "")
        file_path = f.get("file", "")
        line = f.get("line", 0)
        rec = f.get("recommendation", "")
        path_trace = " -> ".join(f.get("path", [])) if isinstance(f.get("path"), list) else ""

        report_lines.append(f"### #{idx}. {f.get('title', rule)} ({sev})")
        report_lines.append(f"- **Rule**: `{rule}`")
        report_lines.append(f"- **Location**: `{file_path}:{line}`")
        report_lines.append(f"- **Description**: {desc}")
        if path_trace:
            report_lines.append(f"- **Data-Flow Taint Trace**: `{path_trace}`")
        report_lines.append(f"- **Recommendation**: {rec}")
        report_lines.append("")

    return json.dumps({
        "target_directory": abs_path,
        "llm_detection_active": llm_active,
        "markdown_report": "\n".join(report_lines),
        "visualizations": svg_files,
        "total_findings": len(findings),
        "findings": findings
    }, indent=2)


@mcp.tool()
def ultron_help() -> str:
    """Get the complete Ultron help and documentation menu including CLI commands, flags, configuration options, MCP tools, and examples."""
    from help import get_help_text
    return get_help_text(use_ansi=False)


if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "").lower()
    port_env = os.environ.get("PORT")

    if port_env or transport == "sse":
        port = int(port_env) if port_env else 8000
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = port
        print(f"Starting Ultron MCP Server in SSE mode on http://0.0.0.0:{port}...")
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")

