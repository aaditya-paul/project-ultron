# Ultron

A multi-agent system that finds security flaws in source code repositories by combining AST analysis, flow graph construction, and specialized security agents powered by a local 8B-parameter LLM.

---

## Current Status

**Phase: AST Analysis & Dependency Graph complete** — cloning, language/framework detection, AST parsing (tree-sitter), dependency graph building, and DOT/SVG visualization are implemented. Taint tracking and security agents are coming next.

```
[GitHub URL]  →  [1. Clone]  →  [2. AST]  →  [3. Flow Graph]  →  (Taint · Agents · Viz · Report)
                   ▲ done        ▲ done       ▲ done              ▲ planned (in order)
```

---

## Usage

```bash
# Run interactively
python ultron.py

# Pass URL directly
python ultron.py https://github.com/user/repo

# List cloned repositories
python ultron.py list

# Scan an already-cloned repository
python ultron.py scan <repo-name>

# Build and export dependency graph visualization
python ultron.py visualise <repo-name>
python ultron.py visualize <repo-name>

# Delete a cloned repository
python ultron.py delete <repo-name>
python ultron.py delete --all

# Show help
python ultron.py --help
```

**Interactive commands:**
| Input | Action |
|---|---|
| `<repository-url>` | clone the target |
| `list` | list cloned repositories |
| `scan <repo-name>` | scan an already-cloned repository |
| `delete <repo-name>` | delete a cloned repository |
| `delete --all` | delete all cloned repositories |
| `visualise <name>` / `visualize <name>` | build and export dependency graph (DOT/SVG) |
| `help` | show usage info |
| `exit` / `quit` / `bye` | exit the program |

If a repository already exists locally, you'll be prompted to pull latest changes instead of re-cloning.

The program **never exits on errors** — clone failures, invalid commands, missing args all just loop back to the prompt. Only `exit`/`quit`/`bye` terminates the session. After any CLI command (including successful clones), the program drops into interactive mode.

---

## Goal

**Automatically identify security vulnerabilities in a GitHub repository and produce a structured, visual, evidence-backed report — fully locally, with no code leaving the machine.**

### Success Criteria (Measurable)

| Metric | Target |
|---|---|
| Clone → Report latency (avg repo ~5k LOC) | < 10 min on a single GPU/CPU box |
| Vulnerability classes covered (MVP) | SQLi, Auth/JWT, XSS, SSRF, Secrets, Business Logic |
| False positive rate on a labeled benchmark (e.g. OWASP Benchmark / DVSA) | Tracked; reduced iteratively |
| Report completeness | Every finding has: file, line, function, tainted path, severity, suggested fix |
| Local-only execution | Zero outbound calls for code or analysis |
| Runs on consumer hardware | 8B model in 4-bit quant, 16GB RAM minimum |

---

## How It Works (MVP)

```
[GitHub URL]
     │
     ▼
[1. Clone]  ── git clone via subprocess into clones/       ✅ MVP done
     │
     ▼
[2. AST Analysis]  ── Parse every supported source file    ✅ MVP done
     │                  (JS/TS, Python, Go, Java…)
     ▼
[3. Flow Graph]  ── Cluster functions into logical flows   ✅ MVP done
     ▼
[4. Taint Graph]  ── Track user input → sanitizers → sinks 🔲 planned
     ▼
[5. Security Agents]  ── 6 specialized agents              🔲 planned
     ▼
[6. Visualization]  ── Dependency graph (DOT/SVG)         ✅ MVP done
     ▼
[7. Report]  ── Aggregated findings + remediation          🔲 planned
```

### Visual Representation (Per-Agent Peace-of-Mind View)

For each agent run, the UI shows:
- The function being inspected (highlighted source)
- The taint path from source → sink
- The agent's reasoning trace
- The candidate finding (if any) with confidence

This makes the black-box LLM auditable, not magical.

---

## Architecture

```
ultron/
├── ultron.py             # Entry point (CLI + interactive loop)
├── colors.py             # ANSI color constants + console setup
├── banner.py             # ULTRON ASCII art + banner()
├── cloner.py             # git clone, pull, list, delete repos
├── detector.py           # language + framework detection
├── help.py               # help text display
├── parser.py             # Tree-sitter AST parsing (multi-language)
├── graph.py              # Dependency graph builder + DOT/SVG render
├── clones/               # Cloned repositories land here
├── workspace/            # Per-project data (manifests, AST, graphs)
├── README.md
└── .gitignore
```

### LLM Strategy

- **Default model:** Qwen2.5-7B or Gemma-2-9B, 4-bit quantized
- **Runtime:** llama.cpp or Ollama, called over a local HTTP API
- **Finetuning (later):** SFT on (code slice, vulnerability class, finding) triples collected from the agent's own labeled runs
- **Why local:** Code never leaves the machine, zero API cost, reproducible runs

---

## Tech Stack (Proposed)

| Layer | Current | Planned |
|---|---|---|---|
| Language | Python 3 (stdlib) | — |
| CLI | `argparse` (manual) | Typer / Rich |
| Git | `subprocess` → `git clone` | — |
| AST | `tree-sitter` (multi-language) | — |
| LLM runtime | — | Ollama / llama.cpp |
| Viz | Graphviz DOT / SVG | React + D3 / Cytoscape.js |
| Report | — | Markdown + JSON |

---

## MVP Scope

**Phase 1 — Clone, Detect, Parse & Graph (current):**
- GitHub URL → clone via `git clone`
- Existing repo detection with pull prompt
- Language detection (Python, JS/TS, Go, Rust, Java, PHP, Ruby, C#, C/C++, …)
- Framework detection (React, Next.js, Django, Flask, Spring Boot, Rails, …)
- Workspace saved to `workspace/<project>/manifest.json` for cross-session use
- Tree-sitter AST parsing — per-file functions, classes, imports, calls
- Dependency graph — file→import and function→call edges
- Graphviz DOT export (SVG if system `dot` binary available)
- `visualise` / `visualize` command
- List cloned repositories
- Delete individual or all repositories (cleans clone + workspace)
- Interactive CLI with retry on failure — **never exits on errors**
- `--help` flag + inline help command
- `exit`/`quit`/`bye` commands

**Phase 2 — Analysis (planned):**
- Taint graph for input → sink
- All 6 security agents running
- Live visualization per agent
- Markdown + JSON report
- Runs fully local with an 8B model

**Out of scope (post-MVP):**
- Live URL scanning / DAST
- Active exploitation (pentest mode)
- Auto-fix PR generation
- Multi-repo / monorepo intelligence
- Authenticated scanning (private repos via token)
- CI/CD integration

---

## Future Features

1. **Live site analysis from a URL**
   - Crawl + map endpoints, replay flows against the live target
2. **Exploitation mode (pentester agent)**
   - Generate PoCs, run safe probes, attempt auth bypass / IDOR chains
3. **Continuous learning loop**
   - Confirmed/rejected findings feed back into a finetune dataset
4. **More vulnerability classes**
   - Deserialization, race conditions, crypto misuse, supply chain
5. **Team & CI mode**
   - PR-level diff scanning, regression detection, SARIF output for GitHub Code Scanning

---

## Getting Started

```bash
# Clone
git clone https://github.com/<you>/ultron
cd ultron

# Install dependencies
pip install -r requirements.txt

# Run
python ultron.py https://github.com/<owner>/<repo>
```

Requires Python 3, system `git`, and `pip install -r requirements.txt` (tree-sitter + language parsers). For SVG rendering, install Graphviz system binaries from https://graphviz.org/download/.

---

## License

TBD
