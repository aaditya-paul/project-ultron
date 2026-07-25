import sys
import os

try:
    os.system("")
except Exception:
    pass

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

RED   = "\033[31m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
WHT   = "\033[97m"
CYAN  = "\033[36m"
GRN   = "\033[32m"
RST   = "\033[0m"
