<picture>
 <img width="1182" height="441" alt="image" src="https://github.com/user-attachments/assets/111364a6-f968-479a-bef8-87e3444fbe5b" />

</picture>

<br>

<div align="center">

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![tests](https://img.shields.io/badge/tests-86%20passing-brightgreen)](#)
[![license](https://img.shields.io/badge/license-MIT-yellow)](#)
[![local-first](https://img.shields.io/badge/local--first-%E2%9C%93-red)](#)

**A local-first multi-agent system that finds security flaws in source code — combining AST analysis, IR-based taint propagation, and specialized LLM agents.**

</div>

<br>

```text
  ultron --mode cloud https://github.com/user/repo
  :: engine   multi-agent security analysis
  :: mode     cloud
  :: version  8b
  :: status   online
```

---

## Quickstart

```bash
pip install -r requirements.txt          # tree-sitter, httpx, graphviz, …
python ultron.py https://github.com/user/repo
```

Requires Python 3.10+, system `git`, and [Graphviz](https://graphviz.org/download/) for SVG rendering.

---

## Features

| | |
|---|---|
| **🔬 AST → IR Pipeline** | Tree-sitter parsing → normalized IR with provenance edges, semantic tags, and cross-file call resolution |
| **🕸️ Taint Engine** | Backward propagation through provenance edges — inter-procedural, sanitizer-aware, deduplicated |
| **🔐 Security Graph** | Source→validation→sink flow chains + Auth / Database / Network subgraphs |
| **🤖 LLM Detector** | Optional LLM verification on taint flows — prompt-optimized, pre-filtered, cached |
| **☁️ Cloud LLM** | Groq / Gemini / NVIDIA with automatic fallback, rate limiting, and retry |
| **📊 Visualizations** | Auto-generated SVGs: dependency graph, taint propagation, security analysis |
| **📦 Zero config** | Works out of the box with local Ollama/llama.cpp — just `pip install` and run |

---

## Usage

### CLI Commands

| Command | Description |
|---|---|
| `ultron <url>` | Clone a repository and run full security analysis |
| `ultron scan <name>` | Run analysis on an already-cloned repo |
| `ultron list` | List cloned repositories |
| `ultron delete <name>` | Delete a cloned repository |
| `ultron delete --all` | Delete all cloned repositories |
| `ultron visualise <name>` | Build & open dependency/taint/security SVGs |
| `ultron config` | Show current configuration |
| `ultron config <key> <val>` | Set a configuration value |
| `ultron config reset` | Reset to defaults |

### Flags

| Flag | Effect |
|---|---|
| `-v` / `--verbose` / `-d` / `--debug` | Enable detailed tracing (LLM prompts, taint steps, raw outputs) |
| `--visualise` / `--visualize` | Open SVGs in browser after scan (paths always printed) |
| `--no-llm` | Skip LLM detection entirely (deterministic rules only) |
| `--mode local` / `--mode cloud` | Override LLM mode for a single command |

### Interactive Mode

Inside the prompt, `list`, `scan`, `delete`, `visualise`, `config`, and `help` all work
without the `ultron` prefix. Type `exit` / `quit` / `bye` to leave.

---

## Configuration

Ultron stores settings in `ultron_config.json`. Manage them with `ultron config`.

| Key | Default | Description |
|---|---|---|
| `llm_mode` | `local` | `local` or `cloud` |
| `use_llm` | `true` | Enable/disable LLM detection |
| `verbose` | `false` | Enable tracing by default |
| `visualise` | `false` | Open SVGs in browser by default |
| `temperature` | `0.1` | LLM generation temperature |
| `max_tokens` | `512` | Max tokens per LLM response |
| `timeout` | `30` | LLM API timeout (seconds) |
| `num_workers` | `3` | Parallel worker threads |
| `llm_url` | — | Local LLM base URL (Ollama, llama.cpp) |
| `enable_cache` | `true` | Cache LLM responses to disk |
| `cache_only` | `false` | Only use cached results |
| `rate_limits` | — | Per-provider throttling config |

### Model Overrides

```
ultron config detector   llama3.1:8b       # model for vulnerability detection
ultron config exploiter  llama3.1:8b       # model for exploitation (planned)
ultron config reporter   llama3.1:8b       # model for report generation (planned)
ultron config default    llama3.1:8b       # fallback model for all agents
```

### Cloud Mode

Enable with `ultron config llm_mode cloud` or per-command with `--mode cloud`.

Set API keys:

```json
{
  "api_keys": {
    "groq": "gsk_...",
    "gemini": "AI...",
    "nvidia": "nvapi-..."
  },
  "cloud_chain": {
    "default": ["groq", "gemini", "nvidia"]
  }
}
```

Built-in optimizations:

- **Rate limiting** — per-provider throttling (configurable req/min + concurrency)
- **Exponential backoff** — retries on 429/5xx (1s → 2s → 4s + jitter, max 30s)
- **Response caching** — SHA-256 keyed by model+prompt+params, persisted to `.ultron_cache/llm_cache.json` (auto-trims to 500 entries)
- **Prompt optimization** — only relevant code sections near source/sink variables (reduces tokens 80–95%)
- **Pre-filtering** — trivially safe flows (logging sinks, env-var sources, single-step paths) skip the LLM
- **JSON retry** — auto-retries up to 2× with stricter prompt on malformed responses

---

## Outputs

Every scan generates three SVG visualizations:

| File | Description |
|---|---|
| `dependency_graph.svg` | Role-colored module dependency graph |
| `taint_graph.svg` | Source → intermediate → sink taint propagation paths |
| `security_graph.svg` | Security analysis: flow chains + Auth / Database / Network subgraphs |

Paths are always printed. Use `--visualise` or `config visualise true` to open them in your browser automatically.

---

## Architecture

```
ultron/
├── ultron.py              # CLI + interactive loop + pipeline orchestrator
├── ir.py                  # Normalized IR data model (11 classes, JSON round-trip)
├── colors.py              # ANSI color constants
├── banner.py              # ULTRON ASCII banner
├── cloner.py              # Git clone, pull, list, delete
├── detector.py            # Language and framework detection
├── help.py                # Help text
├── parser.py              # Tree-sitter AST parsing (multi-language)
├── graph.py               # Dependency graph builder + Graphviz SVG renderer
├── taint_graph.py         # Taint graph SVG renderer (source→sink)
├── security_graph.py      # Security graph builder (flows, subgraphs, summary)
├── rules.py               # Deterministic rule engine
├── llm_detector.py        # LLM-based vulnerability detection on taint flows
├── llm_client.py          # Local & cloud LLM clients (Ollama, Groq, Gemini, NVIDIA)
├── extractors/
│   ├── js_ts.py           # JS/TS IR extractor (tree-sitter CST → IRModule)
│   ├── resolver.py        # Cross-file symbol resolution
│   ├── call_graph.py      # Directed caller→callee graph + DFS paths
│   └── taint_engine.py    # Backward taint propagation engine
├── routes/
│   ├── __init__.py        # Re-exports all route functions
│   ├── repo_routes.py     # Repository management routes
│   ├── config_routes.py   # Configuration management routes
│   ├── pipeline_routes.py # Analysis pipeline routes
│   ├── server.py          # FastAPI HTTP server
│   └── mcp_server.py      # MCP server (18 tools)
├── tests/                 # 86 tests (IR, phase-3 pipeline, config, detector)
├── clones/                # Cloned repositories
├── workspace/             # Per-project data (AST, graphs, IR)
├── project_assets/        # Logos and media
├── requirements.txt
├── ultron_config.json
├── llms.txt              # LLM project description
└── README.md
```

---

## Pipeline

```text
  [URL] ──► [Clone] ──► [AST] ──► [IR Pipeline] ──► [Taint Engine] ──► [Rules + LLM] ──► [Report + SVGs]
               done        done        done               done                  done              done
                                          │
                                     ┌────┴────┐
                                     │ JS/TS   │
                                     │ Extr.   │── Provenance edges
                                     │ Resolver│── Call graph (cross-file)
                                     │ Call    │
                                     │ Graph   │
                                     └─────────┘
```

### Phase 1 — AST Parsing
Tree-sitter walks all detected languages, extracting functions, classes, imports, calls, and returns. Output: `workspace/<repo>/ast/ast.json`.

### Phase 2 — IR Pipeline
- **JS/TS Extractor** — walks tree-sitter CST → `IRFunction`, `IRCall`, `IRAssign`, etc. with provenance edges (assign, return, call-arg flow) and semantic tags (`SINK_DATABASE`, `HTTP_BODY`, `SHELL_EXEC`, …)
- **Symbol Resolver** — global function index with three-tier resolution (exact → receiver-type → qualified)
- **Call Graph** — directed caller→callee graph with DFS path finding and cycle protection
- **Taint Engine** — backward propagation from sinks to sources through provenance edges; inter-procedural, sanitizer-aware (`VALIDATION_GATE` → confidence 0.85), deduplicated
- **Security Graph Builder** — converts IR + call graph + taint paths into flow chains and auth/db/network subgraphs

### Phase 3 — Detection
- **Rules Engine** — deterministic pre-LLM checks: missing auth, unvalidated flows, DB writes without validation
- **LLM Detector** — takes candidate taint paths, extracts relevant code sections (80–95% token reduction), pre-filters safe flows, then checks with an LLM. Retries on malformed JSON. Results cached per session.

---

## API & Integrations

Ultron exposes its full feature set through three layered interfaces: a Python callable API for programmatic use, an HTTP REST API for remote access, and an MCP server for AI-assisted tools.

---

### Python API (`routes/`)

Every terminal command is available as a standalone Python function in the `routes/` package. Each function takes typed parameters and returns structured dicts — no side effects, no console printing.

```python
from routes import list_repos, clone_repo, get_findings, get_config, run_full_analysis

# List all cloned repositories
repos = list_repos()

# Clone and analyze a repository
result = clone_repo("https://github.com/user/repo")

# Run the full analysis pipeline on an existing clone
analysis = run_full_analysis("my-repo")

# Get cached findings from a previous scan
findings = get_findings("my-repo")

# Check configuration
config = get_config()
```

| Module | Functions |
|---|---|
| `routes.repo_routes` | `list_repos`, `clone_repo`, `scan_repo`, `get_repo_status`, `delete_repo`, `delete_all_repos`, `visualise_repo` |
| `routes.pipeline_routes` | `run_detection`, `run_ast_parse`, `run_ir_pipeline`, `run_rules`, `run_llm_detection`, `run_full_analysis`, `get_findings`, `get_security_graph` |
| `routes.config_routes` | `get_config`, `get_config_value`, `set_config_value`, `reset_config`, `set_model_override`, `get_api_keys_status` |

---

### HTTP REST API

A FastAPI server wrapping all route functions. Auto-generated OpenAPI docs at `/docs`.

```bash
pip install fastapi uvicorn
python -m routes.server
# → listening on http://127.0.0.1:8742
```

#### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| **Repositories** | | |
| `GET` | `/api/repos` | List cloned repositories |
| `POST` | `/api/repos/clone` | Clone and analyze |
| `POST` | `/api/repos/scan` | Re-analyze existing clone |
| `GET` | `/api/repos/{name}` | Repository status |
| `DELETE` | `/api/repos/{name}` | Delete a repository |
| `DELETE` | `/api/repos` | Delete all repositories |
| `POST` | `/api/repos/{name}/visualise` | Regenerate SVGs |
| **Analysis** | | |
| `POST` | `/api/repos/{name}/analysis/detection` | Language/framework detection |
| `POST` | `/api/repos/{name}/analysis/ast` | AST parsing |
| `POST` | `/api/repos/{name}/analysis/rules` | Deterministic rules |
| `POST` | `/api/repos/{name}/analysis/llm` | LLM detection |
| `POST` | `/api/repos/{name}/analysis/full` | Full pipeline |
| **Results** | | |
| `GET` | `/api/repos/{name}/findings` | Cached findings |
| `GET` | `/api/repos/{name}/security-graph` | Cached security graph |
| **Configuration** | | |
| `GET` | `/api/config` | Show config |
| `GET` | `/api/config/{key}` | Get single value |
| `POST` | `/api/config` | Set a value |
| `POST` | `/api/config/model-override` | Set per-agent model |
| `GET` | `/api/config/api-keys` | Check API key status |
| `POST` | `/api/config/reset` | Reset to defaults |

```bash
# Example usage
curl -X POST http://127.0.0.1:8742/api/repos/clone \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/user/repo"}'

curl http://127.0.0.1:8742/api/repos
```

---

### MCP Server

The MCP (Model Context Protocol) server exposes Ultron as 18 tools that AI assistants can invoke directly. Compatible with any MCP client — opencode, Claude Desktop, Cursor, VS Code with Copilot Agent Mode, and others.

```bash
# Start with stdio transport (default — for desktop MCP clients)
python routes/mcp_server.py

# Start with SSE transport (for web-based MCP clients)
python routes/mcp_server.py --sse --port 8743
```

#### Tools

| Tool | Description | Category |
|---|---|---|
| `ultron_list_repos` | List all cloned repositories with analysis status | Repository |
| `ultron_clone_repo` | Clone a Git repo and run full security analysis | Repository |
| `ultron_scan_repo` | Re-run full analysis on an existing clone | Repository |
| `ultron_get_repo_status` | Detailed status: workspace, AST, graphs, remote URL | Repository |
| `ultron_delete_repo` | Delete a cloned repository and its workspace | Repository |
| `ultron_visualise_repo` | Regenerate dependency/taint/security SVGs from cached AST | Repository |
| `ultron_run_detection` | Detect languages and frameworks | Analysis |
| `ultron_run_ast_parse` | Parse all source files into an AST | Analysis |
| `ultron_run_rules` | Run deterministic rules (SQLi, path traversal, SSRF, etc.) | Analysis |
| `ultron_run_llm_detection` | Run LLM-powered vulnerability detection | Analysis |
| `ultron_run_full_analysis` | Full pipeline: detection → AST → IR → taint → rules → LLM | Analysis |
| `ultron_get_findings` | Get cached security findings from a previous scan | Results |
| `ultron_get_security_graph` | Get full cached security graph (flows, subgraphs, summary) | Results |
| `ultron_get_config` | Show full configuration | Configuration |
| `ultron_set_config_value` | Set a configuration value | Configuration |
| `ultron_set_model_override` | Set LLM model for a specific agent part | Configuration |
| `ultron_get_api_keys_status` | Check which cloud API keys are configured | Configuration |
| `ultron_reset_config` | Reset configuration to factory defaults | Configuration |

#### Connecting from opencode

Add to your `opencode.json` or `.opencode/global.json`:

```json
{
  "mcpServers": {
    "ultron": {
      "command": "python",
      "args": ["routes/mcp_server.py"]
    }
  }
}
```

#### Connecting from Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ultron": {
      "command": "python",
      "args": ["C:\\path\\to\\ultron\\routes\\mcp_server.py"]
    }
  }
}
```

#### Connecting from VS Code (Copilot Agent Mode)

Configure in VS Code settings or `.vscode/mcp.json`:

```json
{
  "servers": {
    "ultron": {
      "type": "stdio",
      "command": "python",
      "args": ["routes/mcp_server.py"]
    }
  }
}
```

#### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  MCP Client (opencode, Claude Desktop, VS Code, …)                │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ JSON-RPC (stdio / SSE)
┌──────────────────────▼──────────────────────────────────────────────┐
│  routes/mcp_server.py                                              │
│    FastMCP("ultron") — 18 tools                                    │
│                                                                     │
│  ultron_clone_repo    ultron_run_rules      ultron_get_config      │
│  ultron_scan_repo     ultron_run_llm_detection    ...              │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────────┐
│  routes/ package — callable Python API (no side effects)           │
│  routes/repo_routes.py    routes/pipeline_routes.py                │
│  routes/config_routes.py                                           │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────────┐
│  ultron.py modules — core engine                                   │
│  cloner  parser  ir  graph  rules  llm_client  llm_detector       │
│  extractors/js_ts  resolver  call_graph  taint_engine              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Design Principles

> **"The graph answers *how can untrusted input reach sensitive operations?* — not *how is the code written?*"**

- **Local-first by default**: Code never leaves the machine. Zero API cost. Reproducible runs.
- **Opt-in cloud**: Larger models (70B) for complex reasoning passes — with automatic fallback chaining.
- **Never exit on errors**: Clone failures, invalid commands, missing args — all loop back to the prompt.
- **Progressive enhancement**: Deterministic rules run every time. LLM verification adds depth on top.

---

## Tech Stack

| Layer | Current | Planned |
|---|---|---|
| Language | Python 3.10+ | — |
| CLI | argparse | Typer / Rich |
| Git | subprocess | — |
| AST / IR | tree-sitter + normalized IR | Multi-language extractors |
| Taint Engine | Backward propagation, inter-procedural | — |
| LLM | Ollama / llama.cpp (local), Groq / Gemini / NVIDIA (cloud) | SFT fine-tuning |
| Viz | Graphviz DOT/SVG | React + D3 / Cytoscape.js |
| Report | Console + JSON | Markdown + SARIF |

---

## License

MIT
