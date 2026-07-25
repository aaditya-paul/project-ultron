import sys
import os

from colors import CYAN, RED, GRN, WHT, DIM, YLW, RST
from banner import banner
from cloner import clone_repo, list_repos, delete_repo, delete_all_repos, repo_exists, repo_path, extract_repo_name, get_remote_url
from detector import analyze_project, show_detected_types, save_workspace_manifest, WORKSPACE_DIR
from parser import parse_repo, save_ast, show_parse_summary
from graph import load_ast, build_graph, save_graph, render_graph, show_graph_summary
from help import show_help

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
    ast_path = save_ast(WORKSPACE_DIR, repo_name, ast_data)
    if ast_path:
        show_parse_summary(repo_name, ast_data)
        print(f"  {DIM}[*]{RST} AST saved -> {WHT}{ast_path}{RST}")

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
    ast_path = save_ast(WORKSPACE_DIR, name, ast_data)
    if ast_path:
        show_parse_summary(name, ast_data)
        print(f"  {DIM}[*]{RST} AST saved -> {WHT}{ast_path}{RST}")
    print()
    print(f"  {DIM}[*]{RST} scanner not yet implemented — coming in Phase 2.")

def cmd_visualise(name):
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
        print(f"  {GRN}[+]{RST} visualisation saved -> {WHT}{vis_path}{RST}")

def cmd_delete(args):
    if len(args) == 0:
        print(f"  {RED}[-]{RST} specify a repo name or {WHT}--all{RST}")
        return
    if args[0] == "--all":
        delete_all_repos()
    else:
        delete_repo(args[0])

def interactive():
    while True:
        line = input(f"  {CYAN}[~]{RST} target repository : ").strip()
        parts = line.split()
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
    banner()

    if len(sys.argv) > 1:
        arg = sys.argv[1]

        if arg in ("--help", "-h", "help"):
            show_help()
            sys.exit(0)

        if arg == "list":
            list_repos()
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

    interactive()

if __name__ == "__main__":
    main()
