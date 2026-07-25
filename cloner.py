import os
import subprocess

from colors import DIM, WHT, CYAN, GRN, RED, RST

def clone_repo(repo_url):
    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    target_dir = os.path.join(os.getcwd(), "clones", repo_name)

    print()
    print(f"  {DIM}[*] resolving target  -> {WHT}{repo_url}{RST}")
    print(f"  {DIM}[*] local destination -> {WHT}{target_dir}{RST}")
    print()
    print(f"  {CYAN}[*] cloning repository...{RST}")

    result = subprocess.run(
        ["git", "clone", "--progress", repo_url, target_dir],
    )

    print()
    if result.returncode == 0:
        print(f"  {GRN}[+]{RST} {WHT}repository acquired successfully.{RST}")
        return True
    else:
        print(f"  {RED}[-]{RST} {WHT}clone operation failed (exit code {result.returncode}){RST}")
        return False
