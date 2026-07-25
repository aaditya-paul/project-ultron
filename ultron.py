import sys

from colors import CYAN, RED, GRN, WHT, DIM, RST
from banner import banner
from cloner import clone_repo, list_repos, delete_repo, delete_all_repos, repo_exists, repo_path
from help import show_help

def cmd_clone(url):
    if clone_repo(url):
        print(f"  {GRN}[+]{RST} ready.")
    else:
        sys.exit(1)

def cmd_scan(name):
    if not repo_exists(name):
        print(f"  {RED}[-]{RST} {WHT}{name}{RST} not found in clones/. clone it first.")
        return
    print(f"  {DIM}[*]{RST} scanning {WHT}{name}{RST}...")
    print(f"  {DIM}[*]{RST} scanner not yet implemented — coming in Phase 2.")

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

        if cmd == "delete":
            if len(parts) < 2:
                print(f"  {RED}[-]{RST} usage: delete <repo-name> or delete --all")
                continue
            cmd_delete(parts[1:])
            continue

        cmd_clone(line)

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
            sys.exit(0)

        if arg == "scan":
            if len(sys.argv) < 3:
                print(f"  {RED}[-]{RST} usage: ultron scan <repo-name>")
                sys.exit(1)
            cmd_scan(sys.argv[2])
            sys.exit(0)

        if arg == "delete":
            if len(sys.argv) < 3:
                print(f"  {RED}[-]{RST} usage: ultron delete <repo-name> or ultron delete --all")
                sys.exit(1)
            cmd_delete(sys.argv[2:])
            sys.exit(0)

        cmd_clone(arg)
        return

    interactive()

if __name__ == "__main__":
    main()
