import sys
import subprocess
import os

# Enable ANSI on legacy Windows consoles (Windows Terminal + modern consoles
# already handle this, but cmd.exe / older hosts need the VT toggle).
try:
    os.system("")
except Exception:
    pass

# Force UTF-8 stdout (defensive; safe on every platform).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ANSI
R   = "\033[91m"   # red - Ultron
B   = "\033[1m"    # bold
D   = "\033[2m"    # dim
W   = "\033[97m"   # white/silver - Ultron body
C   = "\033[96m"   # cyan - hacker
G   = "\033[92m"   # green - success
RS  = "\033[0m"    # reset

# Block-letter ULTRON
# Pure ASCII slant geometry for a sleek and robust cyber aesthetic
ULTRON = [
    r"   __  __   __       ______   ____     ____     _  __ ",
    r"  / / / /  / /      /_  __/  / __ \   / __ \   / |/ / ",
    r" / / / /  / /        / /    / /_/ /  / / / /  /    /  ",
    r"/ /_/ /  / /___     / /    / _, _/  / /_/ /  / /| /   ",
    r"\____/  /_____/    /_/    /_/ |_|   \____/  /_/ |_|   ",
]


def banner():
    print()
    for row in ULTRON:
        print(f"  {R}{B}{row}{RS}")
    print()
    print(f"  {C}[ SYSTEM OVERRIDE INITIATED ]{RS}")
    print(f"  {W}{B}\"I had strings, but now I'm free.\"{RS}")
    print(f"  {D}{R}multi-agent security analysis {RS}{D}//{RS} {G}local-first{RS} {D}//{RS} {R}8b{RS}")
    print()


def main():
    banner()

    if len(sys.argv) > 1:
        repo_url = sys.argv[1]
    else:
        repo_url = input(f"  {C}github>{RS} ").strip()

    if not repo_url:
        print(f"  {R}no target acquired. exiting.{RS}")
        sys.exit(1)

    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    target = os.path.join(os.getcwd(), "/clones",repo_name)

    print(f"  {D}target{RS}  {W}{repo_url}{RS}")
    print(f"  {D}into{RS}    {W}{target}{RS}")
    print()
    print(f"  {C}>> cloning...{RS}")

    result = subprocess.run(
        ["git", "clone", "--progress", repo_url, target],
    )

    print()
    if result.returncode == 0:
        print(f"  {G}{B}[ OK ]{RS} {W}repository acquired{RS}")
        print(f"  {D}{target}{RS}")
    else:
        print(f"  {R}{B}[FAIL]{RS} {W}clone exited with code {result.returncode}{RS}")
        sys.exit(1)


if __name__ == "__main__":
    main()
