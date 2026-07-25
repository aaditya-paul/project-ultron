"""Ultron MCP Server — exposes security analysis tools via Model Context Protocol.

Run with stdio transport (default, for MCP clients like opencode, Claude Desktop):
    python routes/mcp_server.py

Run with SSE transport (for web-based MCP clients):
    python routes/mcp_server.py --sse --port 8743

Connect from opencode config:
    {
      "mcpServers": {
        "ultron": {
          "command": "python",
          "args": ["routes/mcp_server.py"]
        }
      }
    }
"""

import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from routes import (
    list_repos, clone_repo, scan_repo, get_repo_status,
    delete_repo, delete_all_repos, visualise_repo,
    get_config, set_config_value, set_model_override, get_api_keys_status,
    reset_config,
    run_detection, run_ast_parse,
    run_rules, run_llm_detection, run_full_analysis,
    get_findings, get_security_graph,
)


mcp = FastMCP(
    "ultron",
    instructions="Ultron multi-agent security analysis engine — clone, parse, taint-track, and detect vulnerabilities in source code repos.",
)


# ── Repository management tools ─────────────────────────────────────────────

@mcp.tool(
    name="ultron_list_repos",
    description="List all cloned repositories with their analysis status.",
)
def tool_list_repos() -> str:
    result = list_repos()
    return _fmt(result)


@mcp.tool(
    name="ultron_clone_repo",
    description="Clone a Git repository and run the full security analysis pipeline on it.",
)
def tool_clone_repo(url: str, pull_if_exists: bool = True) -> str:
    result = clone_repo(url, pull_if_exists)
    return _fmt(result)


@mcp.tool(
    name="ultron_scan_repo",
    description="Re-run the full security analysis on an already-cloned repository.",
)
def tool_scan_repo(name: str) -> str:
    result = scan_repo(name)
    return _fmt(result)


@mcp.tool(
    name="ultron_get_repo_status",
    description="Get detailed status of a cloned repository (workspace, AST, graphs, remote URL).",
)
def tool_get_repo_status(name: str) -> str:
    result = get_repo_status(name)
    return _fmt(result)


@mcp.tool(
    name="ultron_delete_repo",
    description="Delete a cloned repository and its workspace data.",
)
def tool_delete_repo(name: str) -> str:
    result = delete_repo(name)
    return _fmt(result)


@mcp.tool(
    name="ultron_visualise_repo",
    description="Regenerate dependency, taint, and security SVG visualisations from cached AST data.",
)
def tool_visualise_repo(name: str) -> str:
    result = visualise_repo(name)
    return _fmt(result)


# ── Analysis pipeline tools ─────────────────────────────────────────────────

@mcp.tool(
    name="ultron_run_detection",
    description="Run language and framework detection on a cloned repository.",
)
def tool_run_detection(repo_name: str) -> str:
    result = run_detection(repo_name)
    return _fmt(result)


@mcp.tool(
    name="ultron_run_ast_parse",
    description="Parse all source files into an AST for a cloned repository.",
)
def tool_run_ast_parse(repo_name: str) -> str:
    result = run_ast_parse(repo_name)
    return _fmt(result)


@mcp.tool(
    name="ultron_run_rules",
    description="Run deterministic security rules (SQLi, path traversal, SSRF, missing auth, etc.) on a repository that has been scanned.",
)
def tool_run_rules(repo_name: str) -> str:
    result = run_rules(repo_name)
    return _fmt(result)


@mcp.tool(
    name="ultron_run_llm_detection",
    description="Run LLM-powered vulnerability detection on a repository (requires LLM to be configured).",
)
def tool_run_llm_detection(repo_name: str) -> str:
    result = run_llm_detection(repo_name)
    return _fmt(result)


@mcp.tool(
    name="ultron_run_full_analysis",
    description="Run the complete analysis pipeline: detection → AST → IR → taint → rules → LLM → visualisations.",
)
def tool_run_full_analysis(repo_name: str) -> str:
    result = run_full_analysis(repo_name)
    return _fmt(result)


# ── Results tools ───────────────────────────────────────────────────────────

@mcp.tool(
    name="ultron_get_findings",
    description="Get cached security findings from a previous scan.",
)
def tool_get_findings(repo_name: str) -> str:
    result = get_findings(repo_name)
    return _fmt(result)


@mcp.tool(
    name="ultron_get_security_graph",
    description="Get the full cached security graph data (flows, subgraphs, summary) from a previous scan.",
)
def tool_get_security_graph(repo_name: str) -> str:
    result = get_security_graph(repo_name)
    return _fmt(result)


# ── Configuration tools ─────────────────────────────────────────────────────

@mcp.tool(
    name="ultron_get_config",
    description="Show the full Ultron configuration (LLM mode, model, API keys status, rate limits, etc.).",
)
def tool_get_config() -> str:
    result = get_config()
    return _fmt(result)


@mcp.tool(
    name="ultron_set_config_value",
    description="Set a configuration value. Valid keys: verbose, visualise, temperature, max_tokens, timeout, num_workers, llm_url, llm_mode, use_llm, enable_cache, cache_only.",
)
def tool_set_config_value(key: str, value: str) -> str:
    result = set_config_value(key, value)
    return _fmt(result)


@mcp.tool(
    name="ultron_set_model_override",
    description="Set an LLM model override for a specific agent part. Valid parts: classifier, detector, exploiter, reporter, default.",
)
def tool_set_model_override(part: str, model: str) -> str:
    result = set_model_override(part, model)
    return _fmt(result)


@mcp.tool(
    name="ultron_get_api_keys_status",
    description="Check which cloud API keys (Groq, Gemini, NVIDIA) are configured.",
)
def tool_get_api_keys_status() -> str:
    result = get_api_keys_status()
    return _fmt(result)


@mcp.tool(
    name="ultron_reset_config",
    description="Reset configuration to factory defaults.",
)
def tool_reset_config() -> str:
    result = reset_config()
    return _fmt(result)


# ── Formatter ───────────────────────────────────────────────────────────────

def _fmt(data) -> str:
    """Convert result dict to a clean JSON string for MCP tool output."""
    if isinstance(data, str):
        return data
    try:
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)
    except Exception:
        return str(data)


# ── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Ultron MCP Server")
    parser.add_argument("--sse", action="store_true", help="Run with SSE transport instead of stdio")
    parser.add_argument("--port", type=int, default=8743, help="Port for SSE transport (default: 8743)")
    args = parser.parse_args()

    if args.sse:
        mcp.settings.port = args.port
        mcp.settings.host = "127.0.0.1"
        print(f"Ultron MCP server starting on SSE http://127.0.0.1:{args.port}", file=sys.stderr)
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
