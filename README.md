# Ultron

A multi-agent system that finds security flaws in source code repositories by combining AST analysis, flow graph construction, and specialized security agents powered by a local 8B-parameter LLM.

---

## Current Status

**Phase 2: Hybrid Classifier & Taint Propagation complete** — cloning, AST parsing, two-pass hybrid classifier (regex patterns + local LLM), variables-level data-flow taint propagation, rule engine, verbose tracing, and dependency/taint visualizations (SVG) are fully implemented. Next step: multi-agent security reasoning (Phase 3).

```
[GitHub URL]  →  [1. Clone]  →  [2. AST]  →  [3. Hybrid Classifier]  →  [4. Taint Tracking]  →  (Agents · Report)
                   ▲ done        ▲ done       ▲ done                  ▲ done              ▲ planned
```

---

## Usage

```bash
# Run interactively
python ultron.py

# Pass URL directly (supports verbose tracing and mode flag)
python ultron.py https://github.com/user/repo [--verbose | -v] [--mode local|cloud]

# List cloned repositories
python ultron.py list

# Scan an already-cloned repository
python ultron.py scan <repo-name> [--verbose | -v] [--mode local|cloud]

# Build and export dependency/taint graph visualizations
python ultron.py visualise <repo-name> [--verbose | -v] [--mode local|cloud]
python ultron.py visualize <repo-name> [--verbose | -v] [--mode local|cloud]

# View/update configuration settings & model overrides
python ultron.py config
python ultron.py config <part/setting> <value>
# e.g., python ultron.py config classifier llama3.1:8b
# e.g., python ultron.py config visualise true
# e.g., python ultron.py config llm_mode cloud

# Reset configuration to defaults
python ultron.py config reset

# Delete a cloned repository
python ultron.py delete <repo-name>
python ultron.py delete --all

# Show help
python ultron.py --help
```

**Interactive commands:**
| Input | Action |
|---|---|
| `<repository-url> [--verbose] [--mode ...]` | clone the target |
| `list` | list cloned repositories |
| `scan <repo-name> [--verbose] [--mode ...]` | scan an already-cloned repository |
| `delete <repo-name>` | delete a cloned repository |
| `delete --all` | delete all cloned repositories |
| `visualise <name> [--verbose] [--mode ...]` / `visualize <name> [--verbose] [--mode ...]` | build/export dependency and taint graphs (DOT/SVG) and print text-based terminal graphs |
| `config` | show current configuration |
| `config <part/setting> <value>` | change a model override or setting (e.g. `config visualise true`) |
| `config reset` | reset configuration to default settings |
| `help` | show usage info |
| `exit` / `quit` / `bye` | exit the program |

### Configuration
Ultron maintains configuration settings in `ultron_config.json`. You can manage settings via the `config` command:
- **Model Overrides**: Change the model for specific parts of the analysis:
  - `classifier` (local model used by the hybrid classifier)
  - `detector` (local model used by the vulnerability detector)
  - `exploiter` (local model used by the exploitation agent)
  - `reporter` (local model used by the reporter agent)
  - `default` (fallback model used by all parts)
- **General Settings**:
  - `visualise` (enable or disable printing text-based terminal graphs on scans by default)
  - `verbose` (turn on verbose tracing by default)
  - `temperature` (LLM generation temperature)
  - `max_tokens` (LLM max tokens per response)
  - `timeout` (LLM API request timeout in seconds)
  - `num_workers` (number of parallel worker threads for batch LLM analysis)
  - `llm_url` (local LLM base URL, e.g. `http://localhost:11434`)
- **LLM Mode**:
  - `llm_mode` — set to `"local"` (default, uses Ollama/llama.cpp) or `"cloud"` (uses remote providers via API)
  - You can also override mode per-command with `--mode local` or `--mode cloud` (no config change needed)
- **Cloud Settings** (only used when `llm_mode` is `"cloud"`):
  - `api_keys` — object with provider keys: `{"groq": "...", "gemini": "...", "nvidia": "..."}`
  - `cloud_chain` — fallback order per agent part: `{"default": ["groq", "gemini", "nvidia"]}`
  - `cloud_models` — model name per provider: `{"groq": "llama-3.3-70b-versatile", "gemini": "gemini-2.0-flash", "nvidia": "meta/llama-3.1-8b-instruct"}`
- **Resetting defaults**: Run `config reset` to restore all options to original system defaults.

### Flags

**Verbose/Debug**: Append `--verbose`, `--debug`, `-v`, or `-d` to commands to see:
- Manual glob/regex pattern-matching findings (reasons for pattern classification).
- Local LLM input prompts and raw completion outputs.
- Raw LLM parser outputs and confidence scores.
- LLM endpoint connection timeouts or errors.
- Detailed variable taint propagation stages (assignments, argument passing, return values, sanitizer logs).

**LLM Mode**: Append `--mode local` or `--mode cloud` to any command to switch between local and cloud LLM providers for that single invocation, overriding the `llm_mode` config setting.

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

## How It Works (Current)

```
[GitHub URL]
     │
     ▼
[1. Clone]  ── git clone via subprocess into clones/              ✅ MVP done
     │
     ▼
[2. AST Parsing]  ── tree-sitter: functions, calls,               ✅ MVP done
     │               classes, imports, assignments, returns
     ▼
[3. Hybrid Classifier]  ── Pattern Pass + Local LLM Pass          ✅ MVP done
     │                      Classifies functions into security roles
     ▼
[4. Taint Propagation]  ── Language-agnostic data flow taint      ✅ MVP done
     │                      Source → variable assignments → sinks
     ▼
[5. LLM Detector]       ── Taint-guided LLM verification          ✅ MVP done
     │                      Feeds relevant flow files to a good LLM
     ▼
[6. Report]             ── Structured findings + remediation      ✅ MVP done
```

### Security Pipeline Details

The pipeline transforms raw AST data into a security-focused representation:

**Phase 1 — AST & Feature Extraction** (`parser.py`, `features.py`):
- Scans AST data across 12 languages to extract function definitions, signatures, imports, calls, local assignments, return expressions, and field accesses.
- Packs these structural features into lightweight context vectors for the classifier.

**Phase 2 — Hybrid Classification** (`classifier.py`, `entities.py`):
- **Pass 1 (Pattern matching)**: Instantly matches primitives against glob lists (e.g. `*db.*` -> database sink) for fast pre-filtering.
- **Pass 2 (Semantic LLM)**: Routes remaining functions to a local LLM client (Ollama/llama.cpp) using precise category descriptions and XML tag responses to classify semantic intent where naming schemes are unpredictable.
- Translates classifications into standard security concepts: `ROUTE`, `SOURCE`, `SINK_DATABASE`, `SINK_SHELL`, `SINK_FILE`, `SINK_NETWORK`, `AUTH`, `VALIDATION`.

**Phase 3 — Taint Propagation** (`taint.py`):
- Traces variable taints language-agnostically along assignment lines, interprocedural argument boundaries, and return values to build the taint graph flow paths.
- Identifies if a tainted path is sanitized via validation functions before reaching a security sink.

**Phase 4 — LLM Vulnerability Detector** (`llm_detector.py`, `rules.py`):
- Takes the candidate flow paths from the taint graph and identifies all files involved in each path.
- Feeds the full source code of the involved files along with the taint flow trace to a specialized local LLM (`detector` model).
- The LLM performs deep, context-aware analysis of the source code and data flow to verify whether a genuine, exploitable vulnerability exists, filtering out false positives.
- If the detector model is offline or unavailable, it falls back to deterministic checks.

**Design principle**: The graph answers *"How can untrusted input reach sensitive operations?"* rather than *"How is the code written?"*

**Language generalization**: Entity detection uses file-path patterns, function-parameter naming conventions, and call-text regex that work across Python, JavaScript/TypeScript, Go, Rust, Java, and other languages supported by tree-sitter.

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
├── entities.py           # Security entity extraction
│                         #   - ROUTE, SOURCE, SINK_*, AUTH, VALIDATION entities
│                         #   - Language-generalized pattern matching
├── security_graph.py     # Security graph construction
│                         #   - Source → validation → sink flow chains
│                         #   - Auth subgraph (protected/unprotected routes)
│                         #   - Database subgraph (read/write operations)
├── rules.py              # Deterministic rule engine (pre-LLM)
│                         #   - Unvalidated source-to-sink flows
│                         #   - Missing authentication on routes
│                         #   - Exposed network requests
├── graph.py              # Dependency graph builder + orchestrator
│                         #   - Filters anonymous/noise functions
│                         #   - Classifies by security role
│                         #   - DOT/SVG render with role-based coloring
│                         #   - Runs full security pipeline
├── llm_client.py         # Local & Cloud LLM clients
│                         #   - LocalLLMClient (Ollama, llama.cpp, OpenAI API)
│                         #   - CloudLLMClient (Groq, Gemini, NVIDIA)
│                         #   - create_llm_client() factory + fallback chain
│                         #   - load_config() with deep merge for all keys
├── clones/               # Cloned repositories land here
├── workspace/            # Per-project data (manifests, AST, graphs)
├── README.md
└── .gitignore
```

### LLM Strategy

- **Default model:** Qwen2.5-7B or Gemma-2-9B, 4-bit quantized
- **Local runtime:** llama.cpp or Ollama, called over a local HTTP API
- **Cloud runtime (experimental):** Groq, Gemini, or NVIDIA via REST API — enable with `llm_mode: cloud` or `--mode cloud`
- **Fallback chain:** Cloud providers are tried in configurable order; if one fails or times out, the next is used automatically
- **Finetuning (later):** SFT on (code slice, vulnerability class, finding) triples collected from the agent's own labeled runs
- **Why local (default):** Code never leaves the machine, zero API cost, reproducible runs
- **Why cloud (opt-in):** Larger models (70B) without local GPU; useful for complex reasoning passes

---

## Tech Stack (Proposed)

| Layer | Current | Planned |
|---|---|---|---|
| Language | Python 3 (stdlib) | — |
| CLI | `argparse` (manual) | Typer / Rich |
| Git | `subprocess` → `git clone` | — |
| AST | `tree-sitter` (multi-language) | — |
| Entity Extraction | Pattern-based (file path, param, call text) | ML-based classification |
| Security Graph | Flow-based (source → validation → sink) | Taint tracking |
| Rules | Deterministic (pre-LLM) | ML-augmented rules |
| LLM runtime | — | Ollama / llama.cpp |
| Viz | Graphviz DOT / SVG (role-colored) | React + D3 / Cytoscape.js |
| Report | — | Markdown + JSON |

---

## MVP Scope

**Phase 1 — Security Analysis Pipeline (current):**
- GitHub URL → clone via `git clone`
- Existing repo detection with pull prompt
- Language detection (Python, JS/TS, Go, Rust, Java, PHP, Ruby, C#, C/C++, …)
- Framework detection (React, Next.js, Django, Flask, Spring Boot, Rails, …)
- Workspace saved to `workspace/<project>/manifest.json` for cross-session use
- Tree-sitter AST parsing — per-file functions, classes, imports, calls (with line scoping)
- **Security Entity Extraction** (`entities.py`):
  - ROUTE entities from API file paths + HTTP method functions
  - SOURCE entities from request parameter access patterns
  - SINK entities (database, shell, file, network, SQL)
  - Auth middleware, JWT, validation entities
  - Language-generalized pattern matching
- **Security Graph Construction** (`security_graph.py`):
  - Source → validation → sink data-flow paths
  - Interprocedural call tracking
  - Auth subgraph (protected vs unprotected routes)
  - Database subgraph (read/write operations)
  - Network subgraph (SSRF surface)
- **Deterministic Rule Engine** (`rules.py`):
  - Pre-LLM checks: missing auth, unvalidated flows, DB write without validation
  - Structured findings with severity and recommendations
  - Extensible rule registry
- **Dependency Graph** (`graph.py`):
  - Noise-filtered function graph (anonymous lambdas, JSX callbacks excluded)
  - Security role classification + layer separation
  - Graphviz DOT/SVG export with role-based coloring
  - Orchestrates full security pipeline
- `visualise` / `visualize` command runs entire pipeline
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

**Cloud mode (optional):** Set API keys in `ultron_config.json`:
```json
{
  "llm_mode": "cloud",
  "api_keys": {
    "groq": "gsk_...",
    "gemini": "AI...",
    "nvidia": "nvapi-..."
  }
}
```
Or override per-command: `python ultron.py --mode cloud https://github.com/user/repo`

---

## License

TBD
