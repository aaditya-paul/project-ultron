import os
import shutil
import subprocess

from colors import DIM, WHT, CYAN, GRN, RED, BOLD, RST

CLONES_DIR = os.path.join(os.getcwd(), "clones")

def extract_repo_name(repo_url):
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name

def repo_path(repo_name):
    return os.path.join(CLONES_DIR, repo_name)

def repo_exists(repo_name):
    return os.path.isdir(repo_path(repo_name))

def pull_repo(target_dir):
    print(f"  {CYAN}[*]{RST} pulling latest changes...")
    result = subprocess.run(
        ["git", "pull", "--progress"],
        cwd=target_dir,
    )
    if result.returncode == 0:
        print(f"  {GRN}[+]{RST} {WHT}repository updated.{RST}")
        return True
    else:
        print(f"  {RED}[-]{RST} {WHT}pull failed (exit code {result.returncode}){RST}")
        return False

def clone_repo(repo_url):
    repo_name = extract_repo_name(repo_url)
    target_dir = repo_path(repo_name)

    if repo_exists(repo_name):
        print(f"  {DIM}[*] {WHT}{repo_name}{RST} {DIM}already exists locally.{RST}")
        answer = input(f"  {CYAN}[~]{RST} pull latest changes and continue? [{GRN}Y{RST}/{RED}n{RST}] ").strip().lower()
        if answer in ("", "y", "yes"):
            if pull_repo(target_dir):
                return repo_name
            return None
        print(f"  {DIM}[*] using existing local copy.{RST}")
        return repo_name

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
        return repo_name
    else:
        print(f"  {RED}[-]{RST} {WHT}clone operation failed (exit code {result.returncode}){RST}")
        return None

def list_repos():
    if not os.path.isdir(CLONES_DIR):
        print(f"  {DIM}[*]{RST} no clones directory found.")
        return

    entries = sorted(os.listdir(CLONES_DIR))
    repos = [e for e in entries if os.path.isdir(os.path.join(CLONES_DIR, e, ".git"))]

    if not repos:
        print(f"  {DIM}[*]{RST} no cloned repositories.")
        return

    print(f"  {CYAN}{BOLD}CLONED REPOSITORIES{RST}")
    print(f"  {DIM}──────────────────────────────────────────────────{RST}")
    for r in repos:
        print(f"    {GRN}•{RST} {WHT}{r}{RST}")

def delete_repo(repo_name):
    target = repo_path(repo_name)
    if not os.path.isdir(target):
        print(f"  {RED}[-]{RST} {WHT}{repo_name}{RST} not found.")
        return False

    answer = input(f"  {CYAN}[~]{RST} delete {WHT}{repo_name}{RST}? [{GRN}y{RST}/{RED}N{RST}] ").strip().lower()
    if answer not in ("y", "yes"):
        print(f"  {DIM}[*]{RST} skipped.")
        return False

    shutil.rmtree(target)
    print(f"  {GRN}[+]{RST} {WHT}{repo_name}{RST} deleted.")
    return True

def delete_all_repos():
    if not os.path.isdir(CLONES_DIR):
        print(f"  {DIM}[*]{RST} no clones directory found.")
        return

    repos = [e for e in os.listdir(CLONES_DIR) if os.path.isdir(os.path.join(CLONES_DIR, e, ".git"))]
    if not repos:
        print(f"  {DIM}[*]{RST} no cloned repositories to delete.")
        return

    print(f"  {RED}{BOLD}WARNING:{RST} this will delete {len(repos)} repositories:")
    for r in repos:
        print(f"    {RED}•{RST} {WHT}{r}{RST}")
    answer = input(f"  {CYAN}[~]{RST} proceed? [{GRN}y{RST}/{RED}N{RST}] ").strip().lower()
    if answer not in ("y", "yes"):
        print(f"  {DIM}[*]{RST} cancelled.")
        return

    for r in repos:
        shutil.rmtree(repo_path(r))
        print(f"  {GRN}[+]{RST} {WHT}{r}{RST} deleted.")
