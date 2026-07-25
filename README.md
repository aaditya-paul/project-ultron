# Ultron

A multi-agent system that finds security flaws in source code repositories by combining AST analysis, flow graph construction, and specialized security agents powered by a local 8B-parameter LLM.

---

## Current Status

**Phase 3: IR-only Pipeline complete** — legacy feature extraction, classifier, entity extraction, and taint runner removed. The pipeline is now IR-native end-to-end:

1. **Clone** → **AST** → **IR Extractors** (tree-sitter, provenance edges, semantic tags)
2. **Symbol Resolution** (cross-file) → **Call Graph** (caller→callee)
3. **IR Taint Engine** (backward propagation, inter-procedural, sanitizer-aware)
4. **Security Graph** (flows, auth/db/network subgraphs) + **Rules** + **LLM Detector**
5. **Auto-generated visualizations**: dependency graph SVG + taint propagation SVG

**86 tests pass** (61 IR/data-model + 22 phase-3 pipeline + 3 other). Next step: multi-agent security reasoning (Phase 4).

```
[GitHub URL]  →  [Clone]  →  [AST]  →  [IR Pipeline]  →  [Taint Engine]  →  (Agents · Report)
                   ▲ done    ▲ done      ▲ done              ▲ done            ▲ planned
                             ┌→ JS/TS Extractor ─→ Provenance Edges ─→┐
                             │   (tree-sitter)    (data flow graph)    │
                             ├→ Symbol Resolver ─→ Call Graph ────────┤
                             │   (cross-file)    (caller→callee)       │
                             └── Security Graph ─→ Rules ─→ LLM ──────┘
                                (IR data → flows)   (findings)
```

---

## Usage

```bash
# Run interactively
python ultron.py

# Pass URL directly
python ultron.py https://github.com/user/repo [--verbose | -v] [--visualise] [--no-llm] [--mode local|cloud]

# List cloned repositories
python ultron.py list

# Scan an already-cloned repository (IR pipeline runs by default on JS/TS files)
python ultron.py scan <repo-name> [--verbose | -v] [--visualise] [--no-llm] [--mode local|cloud]

# Build and export dependency/taint graph visualizations
python ultron.py visualise <repo-name> [--verbose | -v] [--visualise] [--no-llm] [--mode local|cloud]
python ultron.py visualize <repo-name> [--verbose | -v] [--visualise] [--no-llm] [--mode local|cloud]

# View/update configuration settings & model overrides
python ultron.py config
python ultron.py config <part/setting> <value>
# e.g., python ultron.py config detector llama3.1:8b
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
| `<repository-url> [--verbose] [--visualise] [--no-llm] [--mode ...]` | clone the target |
| `list` | list cloned repositories |
| `scan <repo-name> [--verbose] [--visualise] [--no-llm] [--mode ...]` | scan an already-cloned repository |
| `delete <repo-name>` | delete a cloned repository |
| `delete --all` | delete all cloned repositories |
| `visualise <name> [--verbose] [--visualise] [--no-llm] [--mode ...]` / `visualize <name> [--verbose] [--visualise] [--no-llm] [--mode ...]` | build/export dependency and taint graphs, show in terminal |
| `config` | show current configuration |
| `config <part/setting> <value>` | change a model override or setting (e.g. `config detector llama3.1:8b`) |
| `config reset` | reset configuration to default settings |
| `help` | show usage info |
| `exit` / `quit` / `bye` | exit the program |

### Configuration
Ultron maintains configuration settings in `ultron_config.json`. You can manage settings via the `config` command:
- **Model Overrides**: Change the model for specific parts of the analysis:
  - `detector` (local model used by the vulnerability detector)
  - `exploiter` (local model used by the exploitation agent — planned)
  - `reporter` (local model used by the reporter agent — planned)
  - `default` (fallback model for all future agents)
- **General Settings**:
  - `use_llm` (set to `false` to disable LLM vulnerability detection; only deterministic rules run)
  - `visualise` (enable or disable printing SVG file paths after scan)
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

**Visualise**: Append `--visualise` or `--visualize` to any command to show `visualise : enabled` in the banner. Terminal graph summary and taint paths are always shown, SVG file paths are always printed. Can also be set persistently via `config visualise true` in settings.

**No LLM**: Append `--no-llm` to any command to skip LLM-based vulnerability detection entirely. Only deterministic rules run — useful for fast scans or when no LLM is available. Can also be set persistently via `config use_llm false` in settings.

**LLM Mode**: Append `--mode local` or `--mode cloud` to any command to switch between local and cloud LLM providers for that single invocation, overriding the `llm_mode` config setting.

The IR pipeline (provenance edges, call graph, backward taint engine) runs by default on all JS/TS files. No `--ir` flag is needed.

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
[1. Clone]  ── git clone via subprocess into clones/              ✅ done
     │
     ▼
[2. AST Parsing]  ── tree-sitter: function/call/class/import      ✅ done
     │               detection across all languages
     │
     ▼
[3. IR Pipeline]  ── runs by default on all JS/TS files           ✅ done
     │     │
     │     ├─ JS/TS Extractor (tree-sitter CST walker)
     │     │    - IRFunction, IRCall, IRAssign, IRBranch, IRReturn
     │     │    - IRVar, IRAccess, IRLiteral, IRCallExpr
     │     │    - Provenance edges (assign, return, call-arg flow)
     │     │    - Semantic tags (HTTP_BODY, SINK_DATABASE, etc.)
     │     │    - Destructuring support ({a,b}=req.body)
     │     │    - Loop/switch/try/catch/if/throw handling
     │     ├─ Symbol Resolver (cross-file call resolution)
     │     │    - Global function index by lowercase name
     │     │    - Receiver type inference (prisma→PRISMA_CLIENT)
     │     │    - Three-tier resolution (exact→type→qualified)
     │     ├─ Call Graph (caller→callee directed graph, DFS paths)
     │     └─ Security Graph Builder (IR data → flows → subgraphs)
     │
     ▼
[4. IR Taint Engine]   ── Backward propagation via                ✅ done
     │     │               provenance edges, inter-procedural,
     │     │               sanitizer-aware
     │     │   - File-scoped edge lookups (avoids ID collisions)
     │     │   - Sibling exploration cache (prevents exponential)
     │     │   - Cross-module: follow callee returns & caller sites
     │     │   - Dedup by (source, sink, file_path) tuple
     │
     ▼
[5. Rules + LLM Detector]  ── Taint-guided deterministic rules    ✅ done
     │                          + optional LLM verification
     ▼
[6. Report + SVGs]         ── Findings + dependency/taint graphs  ✅ done
```

### Security Pipeline Details

The pipeline transforms raw AST data into a security-focused representation:

**Phase 1 — AST Parsing** (`parser.py`):
- Scans AST data across all detected languages to extract function definitions, calls, classes, imports, assignments, and returns.
- Saves structured AST data to `workspace/<repo>/ast/ast.json`.

**Phase 2 — IR Pipeline** (`ir.py`, `extractors/`):
- **IR Data Model** (`ir.py`): 11 dataclass types (`IRVar`, `IRLiteral`, `IRAccess`, `IRCallExpr`, `IRCall`, `IRAssign`, `IRBranch`, `IRReturn`, `IRFunction`, `Edge`, `Tag`, `CallResolution`, `IRModule`) with auto-generated deterministic hash IDs, polymorphic JSON serialization via `type` discriminator, and full round-trip support.
- **JS/TS Extractor** (`extractors/js_ts.py`): Walks the tree-sitter CST to emit IR functions, statements, and expressions. Post-processing passes build provenance edges (data-flow graph across variables, assignments, calls, and returns) and semantic tags (pattern-matching for `HTTP_BODY`, `SINK_DATABASE`, `SHELL_EXEC`, etc.). Handles destructuring (`{a, b} = req.body` → per-variable edges), loops, try/catch, if/else, switch, and chained calls.
- **Symbol Resolver** (`extractors/resolver.py`): Builds a global function index across all modules. Three-tier resolution strategy: exact name match (1.0 confidence) → receiver type inference (`prisma` → `PRISMA_CLIENT`) → qualified name pattern lookup. Supports cross-file call resolution.
- **Call Graph** (`extractors/call_graph.py`): Directed caller→callee graph with DFS path finding between functions, cycle protection, and JSON serialization.
- **IR Taint Engine** (`extractors/taint_engine.py`): Backward propagation through provenance edges from sinks to sources:
  - **File-scoped edge lookups**: Avoids cross-module ID collisions (node IDs unique only within a file).
  - **Sibling exploration cache**: Prevents exponential blowup on nodes with multiple incoming edges.
  - **Inter-procedural**: Follows callee returns; walks backward from caller call sites.
  - **Sanitizer-aware**: `VALIDATION_GATE` tags mark paths as sanitized (confidence 0.85 vs 0.95).
  - **Deduplication**: By `(source_node_id, sink_node_id, file_path)` tuple.
- **Security Graph Builder** (`security_graph.py`): Converts IR modules + call graph + taint paths into flow chains, auth/db/network subgraphs, and summary dicts.
- **Rules Engine** (`rules.py`): Pre-LLM deterministic checks — missing auth, unvalidated flows, DB writes without validation.
- **LLM Detector** (`llm_detector.py`):
- Takes the candidate flow paths from the taint graph and identifies all files involved in each path.
- Feeds the full source code of the involved files along with the taint flow trace to a specialized local LLM (`detector` model).
- The LLM performs deep, context-aware analysis of the source code and data flow to verify whether a genuine, exploitable vulnerability exists, filtering out false positives.
- If the detector model is offline or unavailable, it falls back to deterministic checks.

**Design principle**: The graph answers *"How can untrusted input reach sensitive operations?"* rather than *"How is the code written?"*

**Language generalization**: The IR extractor currently covers JavaScript/TypeScript. Other languages (Python, Go, Rust, Java, etc.) fall through to AST-level analysis. Multi-language IR extractors are planned.

---

## Architecture

```
ultron/
├── ultron.py             # Entry point (CLI + interactive loop) + pipeline orchestrator
├── ir.py                 # Normalized IR data model (11 classes, auto-hash IDs, JSON round-trip)
├── colors.py             # ANSI color constants + console setup
├── banner.py             # ULTRON ASCII art + banner()
├── cloner.py             # git clone, pull, list, delete repos
├── detector.py           # language + framework detection
├── help.py               # help text display
├── parser.py             # Tree-sitter AST parsing (multi-language)
├── graph.py              # IR dependency graph builder + graphviz SVG renderer
├── security_graph.py     # IR-based security graph builder (flows, subgraphs, summary)
├── rules.py              # Deterministic rule engine (unvalidated flows, missing auth, etc.)
├── taint_graph.py        # IR taint graph renderer (source → intermediate → sink SVG)
├── llm_detector.py       # LLM-based vulnerability detection on taint flows
├── llm_client.py         # Local & Cloud LLM clients (Ollama, Groq, Gemini, NVIDIA)
├── extractors/
│   ├── __init__.py
│   ├── js_ts.py          # JS/TS IR extractor (tree-sitter CST → IRModule)
│   ├── resolver.py       # SymbolResolver: global function index, cross-file call resolution
│   ├── call_graph.py     # CallGraph: directed caller→callee graph, path finding
│   └── taint_engine.py   # TaintEngine: backward propagation, inter-procedural, sanitizer-aware
├── tests/
│   ├── test_ir.py        # 61 tests: IR construction, serialization, provenance, resolution
│   ├── test_phase3.py    # 22 tests: call graph, sink detection, taint engine
│   ├── test_config.py    # Configuration tests
│   └── test_detector.py  # LLM detector tests
├── clones/               # Cloned repositories land here
├── workspace/            # Per-project data (manifests, AST, graphs, security analysis)
├── requirements.txt
├── ultron_config.json
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
| AST / IR | tree-sitter + normalized IR (provenance edges, tags, call graph) | Multi-language IR extractors |
| Taint Engine | Backward propagation via IR provenance edges (inter-procedural, sanitizer-aware) | — |
| Security Graph | Flow-based (source → validation → sink) with auth/db/network subgraphs | — |
| Rules | Deterministic (pre-LLM) + optional LLM verification | ML-augmented rules |
| LLM runtime | Ollama / llama.cpp (local), Groq / Gemini / NVIDIA (cloud) | — |
| Viz | Terminal taint paths + Graphviz DOT/SVG (role-colored) | React + D3 / Cytoscape.js |
| Report | Console findings + `security_graph.json` | Markdown + SARIF |

---

## MVP Scope

**Phase 1 — Security Analysis Pipeline (done):**
- GitHub URL → clone via `git clone`
- Existing repo detection with pull prompt
- Language detection (Python, JS/TS, Go, Rust, Java, PHP, Ruby, C#, C/C++, …)
- Framework detection (React, Next.js, Django, Flask, Spring Boot, Rails, …)
- Workspace saved to `workspace/<project>/manifest.json` for cross-session use
- Tree-sitter AST parsing — per-file functions, classes, imports, calls (with line scoping)
- **IR Pipeline** (`ir.py`, `extractors/`): Runs by default on JS/TS — extract IR, resolve symbols, build call graph, run taint engine
- **Security Graph Construction** (`security_graph.py`):
  - Source → validation → sink data-flow paths from IR data
  - Auth subgraph (protected vs unprotected routes)
  - Database subgraph (read/write operations)
  - Network subgraph (SSRF surface)
- **Deterministic Rule Engine** (`rules.py`):
  - Pre-LLM checks: missing auth, unvalidated flows, DB write without validation
  - Structured findings with severity and recommendations
  - Extensible rule registry
- **Dependency Graph** (`graph.py`):
  - Role-colored Graphviz DOT/SVG export
  - Orchestrates full security pipeline
- `visualise` / `visualize` command runs full pipeline
- Auto-generated SVGs (dependency_graph.svg, taint_graph.svg) on every scan
- List cloned repositories
- Delete individual or all repositories (cleans clone + workspace)
- Interactive CLI with retry on failure — **never exits on errors**
- `--help` flag + inline help command
- `exit`/`quit`/`bye` commands

**Phase 2 — IR Pipeline (done — runs by default on all JS/TS files):**
- **IR Data Model** (`ir.py`): 11 node types with auto-generated deterministic hash IDs (MD5 of `file_path::func::sig`), polymorphic JSON serialization via `type` discriminator, full `to_dict`/`from_dict`/`to_json`/`from_json` round-trip
- **JS/TS Extractor** (`extractors/js_ts.py`): Tree-sitter CST walker producing IRModule with:
  - Function extraction: named/anonymous/arrow/async, parameters, statement blocks or expression bodies
  - Statement coverage: `expression_statement`, `return_statement`, `lexical_declaration`, `if_statement`, `try_statement`, `throw_statement`, `for/for-in/for-of/while/do-while`, `switch`, nested `function_declaration`/`method_definition`/`arrow_function`
  - Expression coverage: identifiers, member expressions (flattened chains), call expressions, strings, numbers, booleans, null, unary/bin, parenthesized, `await` (transparent), template strings, assignment expressions
  - Provenance edge building: `assign`/`assign_target` edges for `IRAssign` (including destructured targets with per-variable edges), `call-target` edges for `IRCall` arguments, `return` edges for `IRReturn`, branch-conditional edges, synthetic assignment edges for `IRCallExpr` results
  - Semantic tagging: `SINK_*` pattern matching against `SINK_PATTERNS` (exec, spawn, Prisma ORM, fetch, file I/O, etc.), `HTTP_BODY` tagging on calls to `req.json()`/`req.body()`/`req.formData()`, and on `IRAccess` expressions rooted in `SOURCE_ROOTS` (req, request, event, ctx, payload, input, body)
  - Chained call receiver tagging: `_tag_expr` recurses into `expr.receiver` so `req.json().user` tags the `.json()` call as `HTTP_BODY`
  - Chained sink tagging: `_tag_call` checks `IRAccess` receivers (e.g., `prisma.lead.create()` tags `.create()`)
  - Fallback arg extraction: `_extract_idents_from_node` collects bare identifiers from object/array literals when `_extract_expr` returns `None`
- **Symbol Resolver** (`extractors/resolver.py`): Global function index by lowercase name; three-tier resolution: exact name match (1.0) → receiver type inference (0.9) e.g. `prisma`→`PRISMA_CLIENT` → qualified name lookup (0.85)
- **Call Graph** (`extractors/call_graph.py`): Directed `caller_fn_id → set[callee_fn_id]` adjacency; reverse lookup; DFS path finding with max depth and cycle protection; JSON serialization
- **IR Taint Engine** (`extractors/taint_engine.py`): Backward propagation engine:
  - **File-scoped edge lookups** via `_edges_by_file[file_path]` to avoid cross-module ID collisions
  - **Sibling exploration cache** (`_sibling_explored_parents`): prevents exponential blowup
  - **Inter-procedural**: follows callee return values; walks backward from caller call sites
  - **Sanitizer-aware**: `VALIDATION_GATE` tags → confidence 0.85 (vs 0.95 unsanitized)
  - **Deduplication**: by `(source_node_id, sink_node_id, file_path)` tuple
  - Sink detection via `detect_sink_type()`: four glob pattern groups (shell→DB→file→network)
- **Security Graph Builder** (`security_graph.py`): Converts IR modules + call graph + taint paths into `security_graph` dict (flows, subgraphs, summary) for rules and LLM detector

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
