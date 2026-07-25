import os
from colors import RED, BOLD, DIM, WHT, GRN, RST
from llm_client import load_config

ULTRON = [
    r"██╗   ██╗██╗  ████████╗██████╗  ██████╗ ███╗   ██╗",
    r"██║   ██║██║  ╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║",
    r"██║   ██║██║     ██║   ██████╔╝██║   ██║██╔██╗ ██║",
    r"██║   ██║██║     ██║   ██╔══██╗██║   ██║██║╚██╗██║",
    r"╚██████╔╝███████╗██║   ██║  ██║╚██████╔╝██║ ╚████║",
    r" ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝"
]

def banner():
    print()
    for row in ULTRON:
        print(f"  {RED}{BOLD}{row}{RST}")
    print()
    print(f"  {DIM}::{RST} {WHT}{BOLD}U L T R O N{RST} {DIM}::{RST}")
    print(f"  {DIM}\"I had strings, but now I'm free.\"{RST}")
    print(f"  {DIM}──────────────────────────────────────────────────{RST}")
    print(f"  {DIM}engine  :{RST} multi-agent security analysis")

    config = load_config()
    mode = os.environ.get("ULTRON_LLM_MODE") or config.get("llm_mode", "local")
    mode_label = "cloud" if mode == "cloud" else "local"
    print(f"  {DIM}mode    :{RST} {GRN}{mode_label}{RST}")

    version = config.get("version", "8b")
    print(f"  {DIM}version :{RST} {version}")

    if os.environ.get("ULTRON_DEBUG") == "1":
        print(f"  {DIM}verbose :{RST} {GRN}enabled{RST}")
    if os.environ.get("ULTRON_VISUALISE") == "1":
        print(f"  {DIM}visualise :{RST} {GRN}enabled{RST}")
    print()
