from colors import RED, BOLD, DIM, WHT, GRN, RST

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
    print(f"  {DIM}mode    :{RST} {GRN}local-first{RST}")
    print(f"  {DIM}version :{RST} 8b")
    print()
