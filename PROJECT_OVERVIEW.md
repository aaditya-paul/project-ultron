# Ultron — Multi-Agent Security Analysis Engine

## What It Is

Ultron is a **local-first, multi-agent static analysis tool** that automatically discovers security vulnerabilities in source code by combining three techniques: **AST parsing**, **IR-based taint propagation**, and **LLM-powered verification**. It clones a Git repository, builds a semantic model of the code, traces how untrusted data flows through it, and reports exploitable paths — all without sending your code to a third party unless you explicitly opt into cloud LLMs.

---

## How It Works (Pipeline)

The entire analysis is a six-phase pipeline. Given a URL or local repo, Ultron runs:

```
[URL] → [Clone] → [AST] → [IR + Taint] → [Rules + LLM] → [Report + SVGs]
```

### Phase 1 — Language Detection & Cloning

- **`cloner.py`** — clones the target Git repo into `clones/` via `git clone`. Supports `list`, `delete`, and re-scan.
- **`detector.py`** — identifies languages and frameworks from:
  - File extensions (`.py`, `.js`, `.ts`, `.go`, `.rs`, `.java`, `.kt`, `.swift`, `.php`, `.rb`, `.cs`, `.c`, `.cpp`, etc.)
  - Project files (`package.json`, `Cargo.toml`, `go.mod`, `requirements.txt`, etc.)
  - Framework heuristics (Django/manage.py, Next.js/next.config, Express/app.listen, Prisma/schema.prisma, etc.)
- Results saved as a workspace manifest in `workspace/<repo>/`.

### Phase 2 — AST Parsing

- **`parser.py`** — uses **tree-sitter** (multi-language grammar library) to parse every source file into a Concrete Syntax Tree.
- Supports **12+ languages**: Python, JavaScript, TypeScript, TSX, Go, Rust, Java, C#, PHP, Ruby, Kotlin, Swift, C/C++.
- Output: `workspace/<repo>/ast/ast.json` — structured JSON with functions, classes, imports, calls, and metadata per file.

### Phase 3 — IR Pipeline (Intermediate Representation)

This is the core semantic analysis. A set of extractors and engines transforms raw AST into a queryable graph.

#### 3a. JS/TS Extractor (`extractors/js_ts.py`)

- Walks tree-sitter CST for JavaScript/TypeScript files and produces **`IRModule`** objects (from `ir.py`).
- **IR data model** (in `ir.py` — 11 dataclass types):
  - `IRFunction` — name, params, body (list of statements), file path, line number
  - `IRVar`, `IRLiteral`, `IRAccess`, `IRCallExpr` — expression nodes (value-producing)
  - `IRCall`, `IRAssign`, `IRBranch`, `IRReturn` — statement nodes
  - `Edge` (provenance edge) — connects a source node to a target node with optional transform info
  - `Tag` — semantic annotation on a node (e.g., `HTTP_BODY`, `SINK_DATABASE`, `VALIDATION_GATE`)
  - `CallResolution` — links a call site to its resolved function definition
- Each `IRModule` corresponds to one source file and holds: functions, provenance edges, semantic tags, and call resolutions.
- **Semantic tags** identify the role of each node: sources (`HTTP_BODY`, `HTTP_PARAMS`, `FILE_READ`, `ENV_VAR`, `COOKIE`), sinks (`SQL_QUERY`, `SHELL_EXEC`, `FILE_ACCESS`, `NETWORK_CALL`), and operations (`VALIDATION_GATE`, `OP_COERCION`, `OP_AUTH`).

#### 3b. Symbol Resolver (`extractors/resolver.py`)

- Builds a **global function index** across all modules (name → function definitions).
- Resolves each `IRCall` to its possible definitions using a **three-tier strategy**:
  1. **Exact match** by function name
  2. **Receiver-type inference** (e.g., `prisma.user.findFirst()` → infers `prisma` is `PRISMA_CLIENT`, searches `PrismaClient.findFirst`)
  3. **Qualified name** as `module.function`
- Populates `call_resolutions` on each module with confidence scores.

#### 3c. Call Graph {`extractors/call_graph.py`}

- Builds a **directed caller→callee graph** from resolved call sites.
- Provides: adjacency list, reverse adjacency, path finding with DFS, cycle protection, function index lookup.
- Used by the taint engine for inter-procedural analysis.

#### 3d. Taint Engine (`extractors/taint_engine.py`)

The taint engine answers the central security question: **"Can untrusted input reach a sensitive sink?"**

- **Sink collection**: scans all `IRCall` and `IRCallExpr` nodes against glob-based sink patterns for databases, shell commands, file operations, and network calls.
- **Backward propagation**: starting from each sink node, walks backward through provenance edges to find source nodes. Key behaviors:
  - **Depth-limited** (max 20 hops) to prevent infinite loops
  - **Cycle detection** via visited set
  - **Inter-procedural**: follows call resolutions into callee functions (walking backward from return statements) and back to caller call sites (walking backward from arguments to parameters)
  - **Sanitizer-aware**: nodes tagged `VALIDATION_GATE` mark a path as sanitized (confidence drops to 0.85)
  - **Operation tracking**: collects `OP_COERCION`, `OP_VALIDATION`, `OP_AUTH` tags along each path
  - **Sibling exploration**: when a node has outgoing edges but no incoming edges, explores sibling nodes that share the same parent
- **Deduplication**: final paths are deduplicated by `(source_node_id, sink_node_id, file_path)`.
- Output: list of `TaintPath` objects, each containing source tag, sink target, intermediate path, sanitization status, and confidence.

### Phase 4 — Security Graph & Rules

#### Security Graph Builder (`security_graph.py`)

- Converts IR modules, call graph, and taint paths into a unified **security graph**:
  - **Flow chains**: source → intermediate nodes → sink with validation status
  - **Subgraphs**: Auth (routes + middleware), Database (queries + models), Network (HTTP calls + URLs)
  - **Summary statistics**: total flows, sanitized vs. unsanitized, source/sink breakdown

#### Deterministic Rules Engine (`rules.py`)

A registry of **decorator-based rules** that run on the security graph:

| Rule | Severity | Description |
|---|---|---|
| `unvalidated-source-to-sink` | high | Untrusted input reaches a sensitive op without validation |
| `sql-injection-via-concat` | high | String concatenation in database queries |
| `path-traversal` | high | User input used in file path construction |
| `ssrf-dynamic-url` | high | User-controlled URL in server-side request |
| `database-write-without-validation` | medium | DB write where user input flows without validation |
| `missing-authentication` | high | API route without auth middleware |

Each rule inspects the security graph's flows and subgraphs, producing findings with severity, description, and remediation recommendations.

### Phase 5 — LLM Detection

#### LLM Client (`llm_client.py`)

Provides a unified interface to multiple LLM backends:

- **Local**: Ollama / llama.cpp via HTTP API
- **Cloud providers** (with automatic fallback chaining):
  - **Groq** (default: `llama-3.3-70b-versatile`)
  - **Gemini** (default: `gemini-2.0-flash`)
  - **NVIDIA** (default: `meta/llama-3.1-8b-instruct`)
- **Features**: rate limiting (per-provider req/min + concurrency), exponential backoff with jitter, response caching (SHA-256 keyed, auto-trims to 500 entries), JSON retry on malformed responses

#### LLM Detector (`llm_detector.py`)

Two operating modes:

1. **Flow-based detection** (when taint paths exist):
   - Pre-filters trivially safe flows (logging sinks, env-var sources, single-step paths)
   - Extracts relevant code sections near source/sink variables (reduces tokens 80–95%)
   - Runs an **agentic loop** with LLM: `READ_FILE`, `READ_FUNCTION`, `RECORD_FACT`, `FINISH`
   - The LLM analyzes the actual source code context to confirm or reject each taint path
   - Results cached per session

2. **General scan** (when no taint paths found):
   - Falls back to autonomous codebase exploration
   - LLM reads files, inspects functions, and reports vulnerabilities the static engine missed
   - Findings backed by source evidence (file path + line numbers)

3. **Auth validation**: LLM examines routes and middleware to validate which routes are actually authenticated, cross-referencing findings from the rules engine.

### Phase 6 — Visualization & Reporting

Three auto-generated SVG diagrams:

| Graph | Tool | What It Shows |
|---|---|---|
| `dependency_graph.svg` | `graph.py` + Graphviz | Module dependency graph colored by role |
| `taint_graph.svg` | `taint_graph.py` | Source → intermediate → sink flow paths |
| `security_graph.svg` | `security_graph.py` | Flow chains + Auth/Database/Network subgraphs |

A terminal summary prints findings with severity colors and taint path details. Results are also saved as JSON to `workspace/<repo>/graph/security_graph.json`.

---

## Architecture

```
ultron/
├── ultron.py              # CLI + interactive loop + pipeline orchestrator
├── ir.py                  # Normalized IR data model (11 classes, JSON round-trip)
├── cloner.py              # Git clone, pull, list, delete
├── detector.py            # Language and framework detection
├── parser.py              # Tree-sitter AST parsing (multi-language)
├── rules.py               # Deterministic rule engine (decorator-based)
├── graph.py               # Dependency graph builder + Graphviz SVG renderer
├── taint_graph.py         # Taint graph SVG renderer (source→sink)
├── security_graph.py      # Security graph builder (flows, subgraphs, summary)
├── llm_client.py          # Local & cloud LLM clients (Ollama, Groq, Gemini, NVIDIA)
├── llm_detector.py        # LLM-based vulnerability detection with agentic loop
├── colors.py / banner.py / help.py  # UI utilities
├── extractors/
│   ├── js_ts.py           # JS/TS IR extractor (tree-sitter CST → IRModule)
│   ├── resolver.py        # Cross-file symbol resolution (3-tier)
│   ├── call_graph.py      # Directed caller→callee graph + DFS paths
│   └── taint_engine.py    # Backward taint propagation engine (inter-procedural)
├── routes/                # Three API layers
│   ├── repo_routes.py     # Repository management functions
│   ├── pipeline_routes.py # Analysis pipeline functions
│   ├── config_routes.py   # Configuration management functions
│   ├── server.py          # FastAPI HTTP server (REST API)
│   └── mcp_server.py      # MCP server (18 tools for AI assistants)
├── tests/                 # 86 tests (IR, pipeline, config, detector)
└── ultron_config.json     # Persistent configuration
```

## API Layers

Ultron exposes its full feature set through three interfaces:

1. **Python API** (`routes/`) — typed functions returning structured dicts: `clone_repo()`, `run_full_analysis()`, `get_findings()`, `get_config()`, etc.
2. **HTTP REST API** — FastAPI server (port 8742) with endpoints for repos, analysis, findings, and config
3. **MCP Server** — 18 tools for AI assistants via Model Context Protocol (stdio or SSE)

## Design Principles

- **"The graph answers *how can untrusted input reach sensitive operations?* — not *how is the code written?*"**
- **Local-first**: code never leaves your machine unless you opt into cloud LLMs
- **Progressive enhancement**: deterministic rules always run; LLM adds depth on top
- **Never exits on errors**: failures loop back to the interactive prompt

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| CLI | argparse |
| Git | subprocess |
| AST | tree-sitter (12+ languages) |
| Data Model | Dataclass-based IR with JSON round-trip |
| Taint Analysis | Backward propagation, inter-procedural, sanitizer-aware |
| LLM | Ollama/llama.cpp (local), Groq/Gemini/NVIDIA (cloud) |
| Visualization | Graphviz DOT/SVG |
| APIs | FastAPI (REST), FastMCP (MCP) |
| Testing | pytest (86 tests) |
