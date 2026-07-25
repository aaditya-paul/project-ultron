# Ultron

A multi-agent system that finds security flaws in source code repositories by combining AST analysis, flow graph construction, and specialized security agents powered by a local 8B-parameter LLM.

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
[1. Clone]  ── git clone via native terminal into a sandboxed workdir
     │
     ▼
[2. AST Analysis]  ── Parse every supported source file (JS/TS, Python, Go, Java…)
     │                  Extract functions, their signatures, and call relationships
     ▼
[3. Flow Graph]  ── Cluster functions into logical flows (auth, db, API, etc.)
     │                Each node = function with file:line, params, calls, sinks
     ▼
[4. Taint Graph]  ── Track user input → sanitizers → sinks
     │                 Build per-flow data-flow chains, e.g.:
     │                   User Input → req.body.email → validateUser()
     │                   → buildQuery() → database.execute()
     ▼
[5. Security Agents]  ── One agent per vulnerability class walks the taint graph
     │                    and the source of each relevant function:
     │                      • SQL Injection Agent
     │                      • Auth Agent  (JWT, session, RBAC)
     │                      • XSS Agent
     │                      • SSRF Agent
     │                      • Secrets Agent  (hardcoded keys, tokens)
     │                      • Business Logic Agent  (IDOR, race, logic flaws)
     ▼
[6. Visualization]  ── Live, per-agent view of the function/taint path under test
     │                  (peace-of-mind UI showing what the agent is reasoning on)
     ▼
[7. Report]  ── Aggregated findings: severity, file:line, taint path, evidence,
                remediation. Exportable as JSON + Markdown.
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
├── cli/                  # Entry point: takes GitHub URL, orchestrates pipeline
├── cloner/               # Spawns native terminal, runs git clone safely
├── analyzer/
│   ├── ast/              # Language-specific parsers → IR
│   ├── flow/             # Builds call graph + clusters into flows
│   └── taint/            # Taint propagation engine
├── agents/               # One module per vulnerability class
│   ├── sqli.py
│   ├── auth.py
│   ├── xss.py
│   ├── ssrf.py
│   ├── secrets.py
│   └── logic.py
├── llm/                  # Local 8B model runner (qwen3.5 / gemma4 via llama.cpp / ollama)
├── viz/                  # Web UI for live agent trace
├── reporter/             # Aggregates findings → JSON + Markdown
└── benchmarks/           # Curated vulnerable repos for measuring FP/FN
```

### LLM Strategy

- **Default model:** Qwen2.5-7B or Gemma-2-9B, 4-bit quantized
- **Runtime:** llama.cpp or Ollama, called over a local HTTP API
- **Finetuning (later):** SFT on (code slice, vulnerability class, finding) triples collected from the agent's own labeled runs
- **Why local:** Code never leaves the machine, zero API cost, reproducible runs

---

## Tech Stack (Proposed)

| Layer | Choice | Why |
|---|---|---|
| Language | Python | Best ecosystem for AST, static analysis, LLM glue |
| AST | `tree-sitter` (multi-language) | Fast, robust, language-agnostic IR |
| LLM runtime | Ollama / llama.cpp | Local, easy model swap |
| Viz | React + D3 / Cytoscape.js | Graph rendering for flow + taint |
| CLI | Typer / Rich | Clean terminal UX |
| Report | Markdown + JSON | Human + machine consumable |

---

## MVP Scope

**In scope:**
- GitHub URL → clone
- AST analysis for **at least 2 languages** (start with Python + JS/TS)
- Call graph + flow clustering
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

## Getting Started (planned)

```bash
# Install
git clone https://github.com/<you>/ultron
cd ultron
pip install -e .

# Run (local model must be pulled, e.g. via ollama)
ollama pull qwen2.5:7b
ultron analyze https://github.com/<owner>/<repo>
```

---

## License

TBD
