import sys

from colors import CYAN, RED, RST
from banner import banner
from cloner import clone_repo
from help import show_help

def main():
    banner()

    if len(sys.argv) > 1:
        if sys.argv[1] in ("--help", "-h", "help"):
            show_help()
            sys.exit(0)
        if not clone_repo(sys.argv[1]):
            sys.exit(1)
        return
    else:
        while True:
            repo_url = input(f"  {CYAN}[~]{RST} target repository : ").strip()

            if repo_url.lower() in ("help", "--help", "-h"):
                show_help()
                continue

            if not repo_url or repo_url.lower() in ("exit", "quit", "bye"):
                print(f"  {RED}[!] exiting.{RST}")
                sys.exit(1)

            if clone_repo(repo_url):
                break

            print()
        return

if __name__ == "__main__":
    main()
