import os
from colors import CYAN, BOLD, DIM, GRN, YLW, RST
from llm_client import load_config


def get_help_text(use_ansi: bool = False) -> str:
    config = load_config()
    version = config.get("version", "8b")
    mode = os.environ.get("ULTRON_LLM_MODE") or config.get("llm_mode", "local")

    c_cyan = CYAN if use_ansi else ""
    c_bold = BOLD if use_ansi else ""
    c_dim = DIM if use_ansi else ""
    c_grn = GRN if use_ansi else ""
    c_ylw = YLW if use_ansi else ""
    c_rst = RST if use_ansi else ""

    lines = [
        "",
        f"  {c_cyan}{c_bold}ULTRON — multi-agent security analysis & remediation{c_rst}",
        f"  {c_dim}version: {version}  mode: {c_grn}{mode}{c_rst}",
        "",
        f"  {c_cyan}{c_bold}COMMANDS{c_rst}",
        f"  {c_dim}─────────────────────────────────────────────────────────────{c_rst}",
        f"    {c_grn}ultron <url>{c_rst} {c_dim}[--fix] [flags]{c_rst}",
        f"      Clone a repository and run full security analysis.",
        "",
        f"    {c_grn}ultron scan <name-or-directory>{c_rst} {c_dim}[--fix] [flags]{c_rst}",
        f"      Run security analysis on an existing repo or local folder.",
        f"      Pass --fix to invoke LLM Refactoring Agents to auto-patch vulnerable code.",
        "",
        f"    {c_grn}ultron install-hook{c_rst} {c_dim}[target_dir] [--no-fix]{c_rst}",
        f"      Install project-specific Git pre-commit hook into .git/hooks/pre-commit.",
        f"      Disabled by default. Git will automatically scan code before commits when enabled.",
        "",
        f"    {c_grn}ultron uninstall-hook{c_rst} {c_dim}[target_dir]{c_rst}",
        f"    {c_grn}ultron remove-hook{c_rst} {c_dim}[target_dir]{c_rst}",
        f"      Uninstall/remove Git pre-commit hook from the target repository.",
        "",
        f"    {c_grn}ultron list{c_rst}",
        f"      List all cloned repositories.",
        "",
        f"    {c_grn}ultron delete <name>{c_rst}",
        f"    {c_grn}ultron delete --all{c_rst}",
        f"      Delete a cloned repository (or all of them).",
        "",
        f"    {c_grn}ultron visualise <name>{c_rst} {c_dim}[flags]{c_rst}",
        f"    {c_grn}ultron visualize <name>{c_rst} {c_dim}[flags]{c_rst}",
        f"      Build and open dependency/taint/security SVGs in browser.",
        "",
        f"    {c_grn}ultron config{c_rst}",
        f"      Show the current configuration.",
        f"    {c_grn}ultron config <key> <value>{c_rst}",
        f"      Set a configuration value (e.g. {c_grn}config llm_mode cloud{c_rst}).",
        f"    {c_grn}ultron config reset{c_rst}",
        f"      Restore all settings to defaults.",
        "",
        f"    {c_grn}ultron --help{c_rst}",
        f"      Show this help message.",
        "",
        f"  {c_cyan}{c_bold}FLAGS{c_rst}",
        f"  {c_dim}─────────────────────────────────────────────────────────────{c_rst}",
        f"    {c_grn}--fix{c_rst}",
        f"      Enable LLM Agent security remediation (Autofix mode: True).",
        f"      Prompts specialized refactoring agents to rewrite vulnerable files.",
        "",
        f"    {c_grn}-v{c_rst}, {c_grn}--verbose{c_rst}, {c_grn}-d{c_rst}, {c_grn}--debug{c_rst}",
        f"      Show detailed tracing: LLM prompts, raw outputs,",
        f"      taint propagation steps, pattern matching results.",
        "",
        f"    {c_grn}--visualise{c_rst}, {c_grn}--visualize{c_rst}",
        f"      Open generated SVGs in default browser.",
        "",
        f"    {c_grn}--no-llm{c_rst}",
        f"      Skip LLM vulnerability detection (deterministic rules only).",
        "",
        f"    {c_grn}--mode local{c_rst} | {c_grn}cloud{c_rst}",
        f"      Override LLM mode for this single command.",
        "",
        f"  {c_cyan}{c_bold}MCP SERVER TOOLS (ultron_mcp_server.py){c_rst}",
        f"  {c_dim}─────────────────────────────────────────────────────────────{c_rst}",
        f"    {c_grn}ultron_scan(target_dir){c_rst}           Full static security audit (JSON report)",
        f"    {c_grn}ultron_auto_fix(target_dir){RST}       Audit + LLM Agent auto-remediation",
        f"    {c_grn}ultron_get_report(target_dir){RST}     Markdown security report & SVG graph paths",
        f"    {c_grn}ultron_install_git_hook(dir){c_rst}     Install project pre-commit hook in .git/hooks",
        f"    {c_grn}ultron_remove_git_hook(dir){c_rst}      Remove project pre-commit hook from .git/hooks",
        f"    {c_grn}ultron_check_diff(target_dir){c_rst}     Incremental scan on uncommitted git diff",
        f"    {c_grn}ultron_help(){c_rst}                    Show complete Ultron help & documentation menu",
        "",
        f"  {c_cyan}{c_bold}EXAMPLES{c_rst}",
        f"  {c_dim}─────────────────────────────────────────────────────────────{c_rst}",
        f"    {c_dim}# Scan and auto-fix local codebase with LLM Agents{c_grn}",
        f"    ultron scan . --fix",
        "",
        f"    {c_dim}# Install Git pre-commit hook in current repo{c_grn}",
        f"    ultron install-hook .",
        "",
    ]
    return "\n".join(lines)


def show_help():
    print(get_help_text(use_ansi=True))
