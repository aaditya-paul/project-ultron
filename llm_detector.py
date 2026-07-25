import os
import json
import re
import hashlib
from colors import CYAN, GRN, YLW, RED, RST, BOLD, DIM, WHT
from ir import IRFunction, IRCall, IRAssign, IRBranch, IRReturn

# In-memory cache for detector responses (complements cloud-level cache)
_detector_cache = {}

TRIVIALLY_SAFE_SINKS = {
    "console.log", "print", "printf", "fmt.Println", "logger.info",
    "logger.debug", "log.Info", "log.Debug", "os.Stdout.WriteString",
}

TRIVIALLY_SAFE_SOURCE_PREFIXES = (
    "os.environ.get", "os.getenv", "env(", "config(",
)

# Maximum characters of source code to include per file
MAX_CODE_CHARS_PER_FILE = 6000


def _flow_cache_key(flow, model_name, temperature):
    raw = f"{json.dumps(flow, sort_keys=True)}|{model_name}|{temperature}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ── Node-to-function index from IR data ─────────────────────────────────────

def _index_stmt_nodes(stmt, fn_id, cache):
    cache[stmt.id] = fn_id
    if isinstance(stmt, IRCall):
        if stmt.receiver:
            _index_expr_nodes(stmt.receiver, fn_id, cache)
        for a in stmt.args:
            _index_expr_nodes(a, fn_id, cache)
    elif isinstance(stmt, IRAssign):
        if stmt.value:
            _index_expr_nodes(stmt.value, fn_id, cache)
    elif isinstance(stmt, IRBranch):
        if stmt.condition:
            _index_expr_nodes(stmt.condition, fn_id, cache)
        for s in stmt.true_body:
            _index_stmt_nodes(s, fn_id, cache)
        for s in stmt.false_body:
            _index_stmt_nodes(s, fn_id, cache)
    elif isinstance(stmt, IRReturn):
        if stmt.value:
            _index_expr_nodes(stmt.value, fn_id, cache)

def _index_expr_nodes(expr, fn_id, cache):
    cache[expr.id] = fn_id
    if hasattr(expr, 'root') and expr.root:
        _index_expr_nodes(expr.root, fn_id, cache)
    if hasattr(expr, 'args'):
        for a in expr.args:
            _index_expr_nodes(a, fn_id, cache)
    if hasattr(expr, 'receiver') and expr.receiver:
        _index_expr_nodes(expr.receiver, fn_id, cache)

def _build_node_fn_index(ir_modules):
    cache = {}
    for mod in ir_modules:
        for fn in mod.functions:
            cache[fn.id] = fn.id
            for stmt in fn.body:
                _index_stmt_nodes(stmt, fn.id, cache)
    return cache


# ── Function boundary computation ──────────────────────────────────────────

def _stmt_max_line(stmt):
    m = getattr(stmt, 'line', 0) or 0
    if isinstance(stmt, IRBranch):
        for s in stmt.true_body:
            m = max(m, _stmt_max_line(s))
        for s in stmt.false_body:
            m = max(m, _stmt_max_line(s))
    elif isinstance(stmt, IRCall):
        pass
    elif isinstance(stmt, IRAssign):
        pass
    elif isinstance(stmt, IRReturn):
        pass
    return m

def _build_function_boundaries(ir_modules):
    boundaries = {}
    for mod in ir_modules:
        fns = sorted(mod.functions, key=lambda f: f.line)
        for i, fn in enumerate(fns):
            start = fn.line
            if i + 1 < len(fns):
                end = fns[i + 1].line - 1
            else:
                max_body = _stmt_max_line_from_list(fn.body)
                end = max(start, max_body) + 5
            boundaries.setdefault(mod.file_path, []).append({
                "fn_id": fn.id,
                "name": fn.name,
                "start": start,
                "end": end,
            })
    return boundaries

def _stmt_max_line_from_list(stmts):
    m = 0
    for stmt in stmts:
        m = max(m, _stmt_max_line(stmt))
    return m


# ── Function-level source extraction ───────────────────────────────────────

def _extract_full_function_context(target_path, flow, node_fn_map, fn_boundaries, max_chars=MAX_CODE_CHARS_PER_FILE):
    """Extract complete function bodies for all functions in the taint chain."""
    expressions = flow.get("expressions", [])
    path_steps = flow.get("path", [])

    if not expressions and not path_steps:
        return ""

    # Gather all node IDs from the taint path
    node_ids = set()
    for nid in expressions:
        node_ids.add(nid)
    for step in path_steps:
        if "::" in step:
            parts = step.split("::")
            if len(parts) >= 2:
                node_ids.add(parts[1])

    # Map node IDs to function IDs
    involved_fn_ids = set()
    for nid in node_ids:
        fn_id = node_fn_map.get(nid)
        if fn_id:
            involved_fn_ids.add(fn_id)

    # Group function boundaries by file
    file_fn_map = {}
    for fpath, fns in fn_boundaries.items():
        for fn_info in fns:
            if fn_info["fn_id"] in involved_fn_ids:
                file_fn_map.setdefault(fpath, []).append(fn_info)

    if not file_fn_map:
        return ""

    sections = []
    total_chars = 0
    for fpath in sorted(file_fn_map):
        abs_file = os.path.join(target_path, fpath)
        if not os.path.isfile(abs_file):
            continue
        try:
            with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
                source_lines = f.readlines()
        except Exception:
            continue

        file_len = len(source_lines)
        fns = sorted(file_fn_map[fpath], key=lambda x: x["start"])
        for fn_info in fns:
            start = max(0, fn_info["start"] - 1)
            end = min(file_len, fn_info["end"])
            if start >= end:
                continue
            block = "".join(source_lines[start:end]).rstrip()
            if len(block) > max_chars:
                block = block[:max_chars] + "\n    // ... (truncated)"
            header = f"--- FILE: {fpath} :: {fn_info['name']}() (lines {fn_info['start']}-{fn_info['end']}) ---"
            snippet = f"{header}\n{block}"
            if total_chars + len(snippet) > max_chars * 3:
                remaining = max_chars * 3 - total_chars
                if remaining > 200:
                    sections.append(snippet[:remaining] + "\n    // ... (truncated)")
                break
            sections.append(snippet)
            total_chars += len(snippet)

    return "\n\n".join(sections)


# ── Structured flow report builder ──────────────────────────────────────────

def _build_node_label_map(ir_modules):
    """Build node_id → {label, file_path, line} lookup from IR modules."""
    from security_graph import build_node_index, _expr_label, _stmt_label
    return build_node_index(ir_modules)


def _build_flow_report(flow, node_label_map, target_path):
    """Build a structured step-by-step trace from source to sink."""
    exprs = flow.get("expressions", [])
    ops = flow.get("operations", [])
    source_tag = flow.get("source", "")
    sink = flow.get("sink", "")
    sink_type = flow.get("sink_type", "")

    if not exprs:
        return ""

    lines = []
    lines.append("FLOW REPORT (step-by-step trace from source to sink):")

    # Source
    src_info = node_label_map.get(exprs[0]) if exprs else None
    read_lines_cache = {}
    def _get_source_line(file_path, line_num):
        if not file_path or not line_num:
            return ""
        abs_path = os.path.join(target_path, file_path)
        if abs_path not in read_lines_cache:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    read_lines_cache[abs_path] = f.readlines()
            except Exception:
                read_lines_cache[abs_path] = []
        all_lines = read_lines_cache[abs_path]
        if 1 <= line_num <= len(all_lines):
            return all_lines[line_num - 1].rstrip()[:160]
        return ""

    src_loc = f"{src_info['file_path']}:{src_info['line']}" if src_info and src_info.get('line') else ""
    src_line = ""
    if src_loc:
        parts = src_loc.rsplit(":", 1)
        if len(parts) == 2:
            src_line = _get_source_line(parts[0], int(parts[1]))
    lines.append(f"  Source: {source_tag}" + (f" at {src_loc}" if src_loc else ""))
    if src_line:
        lines.append(f"    -> {src_line}")

    mid = exprs[1:-1] if len(exprs) > 2 else []
    for i, node_id in enumerate(mid):
        info = node_label_map.get(node_id, {})
        label = info.get("label", node_id)
        fpath = info.get("file_path", "")
        ln = info.get("line", 0)
        loc = f"{fpath}:{ln}" if ln else ""

        snippet = _get_source_line(fpath, ln) if ln else ""
        step = f"  Step {i+1}: {label}"
        if loc:
            step += f" ({loc})"
        if snippet:
            step += f"\n    -> {snippet}"
        lines.append(step)

    # Sink
    sink_info = node_label_map.get(exprs[-1]) if len(exprs) > 1 else None
    sink_loc = f"{sink_info['file_path']}:{sink_info['line']}" if sink_info and sink_info.get('line') else ""
    sink_line = ""
    if sink_loc:
        parts = sink_loc.rsplit(":", 1)
        if len(parts) == 2:
            sink_line = _get_source_line(parts[0], int(parts[1]))
    lines.append(f"  Sink: {sink} ({sink_type})" + (f" at {sink_loc}" if sink_loc else ""))
    if sink_line:
        lines.append(f"    -> {sink_line}")

    # Security-relevant annotations
    if ops:
        lines.append(f"  Security operations detected: {', '.join(sorted(set(ops)))}")
    else:
        lines.append("  Security operations detected: none")

    if "OP_AUTH" in ops:
        lines.append("  Auth: authentication call present on this path")
    else:
        lines.append("  Auth: no explicit authentication call on this path")

    if "OP_COERCION" in ops:
        lines.append("  Note: input goes through type coercion (prevents NoSQL operator injection)")
    if "OP_VALIDATION" in ops:
        lines.append("  Note: input goes through format validation (.test(), .match(), zod/joi)")

    return "\n".join(lines)


def _is_trivially_safe(flow):
    sink_type = flow.get("sink_type", "")
    sink = flow.get("sink", "")
    source = flow.get("source", "")
    path_labels = flow.get("path_labels", [])
    ops = flow.get("operations", [])

    # If the sink is a known logging/printing function, skip
    if sink in TRIVIALLY_SAFE_SINKS or sink.split(".")[-1] in TRIVIALLY_SAFE_SINKS:
        return True

    # If the sink type is "log" or "print", skip
    if sink_type.lower() in ("log", "print", "debug"):
        return True

    # If source is from an env/config (usually safe)
    if source.startswith(TRIVIALLY_SAFE_SOURCE_PREFIXES):
        return True

    # If source is from session or environment (not attacker-controlled)
    if source in ("SOURCE_SESSION", "SOURCE_ENV"):
        return True

    # If path has coercion + no interesting sink (like DB query), skip
    if "OP_COERCION" in ops and "SINK_DATABASE" not in sink_type and "SINK_SHELL" not in sink_type:
        return True

    # If path is very short (source and sink are the same variable)
    if len(path_labels) <= 1:
        return True

    return False

class GlobalMemory:
    def __init__(self):
        self.facts = []
        self.discovery_data = {}

    def add_fact(self, fact: str):
        if fact and fact not in self.facts:
            self.facts.append(fact)

    def to_string(self) -> str:
        s = "GLOBAL REPOSITORY CONTEXT & MEMORY:\n"
        if self.discovery_data:
            s += f"- Discovery Info: {json.dumps(self.discovery_data)}\n"
        if self.facts:
            s += "- Logged Facts:\n"
            for f in self.facts:
                s += f"  * {f}\n"
        else:
            s += "- No facts logged yet.\n"
        return s


def run_llm_discovery(target_path, detector_client, ir_modules, verbose=False) -> GlobalMemory:
    memory = GlobalMemory()
    
    # 1. Inspect package.json if it exists
    pkg_json_path = os.path.join(target_path, "package.json")
    pkg_data = {}
    if os.path.isfile(pkg_json_path):
        try:
            with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                pkg_data = {
                    "dependencies": data.get("dependencies", {}),
                    "devDependencies": data.get("devDependencies", {})
                }
        except Exception:
            pass

    # 2. Collect files list
    file_list = []
    if ir_modules:
        file_list = [mod.file_path for mod in ir_modules]
    else:
        for root, _, files in os.walk(target_path):
            for file in files:
                rel = os.path.relpath(os.path.join(root, file), target_path)
                file_list.append(rel)

    prompt = f"""You are a security architect reviewing a software repository.
Your task is to analyze the metadata below and output a summary of the project architecture, dependencies, and potential security considerations.

PROJECT METADATA:
- Files in repository: {file_list[:100]}
- Package Dependencies: {json.dumps(pkg_data, indent=2)}

Please output a JSON object summarizing your findings:
{{
  "frameworks": ["Express", "React", etc.],
  "database_client": "Mongoose", "Prisma", "Knex", etc., or "None",
  "auth_mechanisms": ["JWT", "Session", "None"],
  "validation_libraries": ["Zod", "Joi", "None"],
  "security_middlewares": ["Helmet", "Cors", "None"],
  "notes": "Any key security observations about this structure"
}}

Output ONLY valid JSON. No markdown formatting, no code blocks."""

    if verbose:
        print("    [*] Running global discovery pass...")

    try:
        response = detector_client.complete(prompt, max_tokens=600)
        cleaned = response.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        data = json.loads(cleaned)
        memory.discovery_data = data
        if verbose:
            print(f"    [+] Discovery data populated: {list(data.keys())}")
    except Exception as e:
        if verbose:
            print(f"    [-] Global discovery failed: {e}")

    return memory


def _extract_from_boundaries(target_path, file_fn_map, max_chars=MAX_CODE_CHARS_PER_FILE):
    sections = []
    total_chars = 0
    for fpath in sorted(file_fn_map):
        abs_file = os.path.join(target_path, fpath)
        if not os.path.isfile(abs_file):
            continue
        try:
            with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
                source_lines = f.readlines()
        except Exception:
            continue

        file_len = len(source_lines)
        fns = sorted(file_fn_map[fpath], key=lambda x: x["start"])
        for fn_info in fns:
            start = max(0, fn_info["start"] - 1)
            end = min(file_len, fn_info["end"])
            if start >= end:
                continue
            block = "".join(source_lines[start:end]).rstrip()
            if len(block) > max_chars:
                block = block[:max_chars] + "\n    // ... (truncated)"
            header = f"--- FILE: {fpath} :: {fn_info['name']}() (lines {fn_info['start']}-{fn_info['end']}) ---"
            snippet = f"{header}\n{block}"
            if total_chars + len(snippet) > max_chars * 3:
                break
            sections.append(snippet)
            total_chars += len(snippet)

    return "\n\n".join(sections)


def run_agentic_flow_analysis(target_path, flow, node_fn_map, fn_boundaries, global_memory, detector_client, node_label_map=None, verbose=False) -> dict:
    flow_id = flow.get("id", "flow")
    source = flow.get("source", "")
    sink = flow.get("sink", "")
    sink_type = flow.get("sink_type", "")
    path_labels = flow.get("path_labels", [])
    expressions = flow.get("expressions", [])

    # Build structured flow report first (preferred)
    flow_report = ""
    if node_label_map:
        flow_report = _build_flow_report(flow, node_label_map, target_path)

    # Fallback: raw function context
    raw_context = ""
    if node_fn_map and fn_boundaries and not flow_report:
        involved_fn_ids = set()
        src_node_id = expressions[0] if expressions else None
        dst_node_id = expressions[-1] if len(expressions) > 1 else None
        if src_node_id and node_fn_map.get(src_node_id):
            involved_fn_ids.add(node_fn_map[src_node_id])
        if dst_node_id and node_fn_map.get(dst_node_id):
            involved_fn_ids.add(node_fn_map[dst_node_id])

        file_fn_map = {}
        for fpath, fns in fn_boundaries.items():
            for fn_info in fns:
                if fn_info["fn_id"] in involved_fn_ids:
                    file_fn_map.setdefault(fpath, []).append(fn_info)

        raw_context = _extract_from_boundaries(target_path, file_fn_map)

    if not raw_context:
        involved_files = set()
        for step in flow.get("path", []):
            if "::" in step:
                involved_files.add(step.split("::")[0])
        raw_context = _legacy_snippet_extract(target_path, flow, involved_files, max_chars=2000)

    # Use flow report as primary context, append raw source as secondary
    initial_context = flow_report if flow_report else raw_context
    if flow_report and raw_context:
        initial_context = flow_report + "\n\nFULL FUNCTION CONTEXT (for reference):\n" + raw_context

    history = []

    system_prompt = f"""You are an agentic security code auditor.
Your goal is to determine if a potential data-flow (taint) path represents a genuine, exploitable security vulnerability.
You have access to a Global Memory representing context about the repository, and you can request to inspect files or functions to trace the business logic and verify sanitizers.

POTENTIAL VULNERABILITY FLOW DETAILS:
- Flow ID: {flow_id}
- Source (attacker input): {source}
- Sink (sensitive operation): {sink} (Type: {sink_type})
- Data-Flow Path Trace: {' -> '.join(path_labels)}

{initial_context}

{global_memory.to_string()}

YOUR TOOLS (ACTIONS):
You can perform one action per turn by returning a JSON block matching one of these formats:

1. Read a specific file to trace validation/middleware/logic:
{{"action": "READ_FILE", "path": "path/to/file", "start_line": 1, "end_line": 50}}

2. Read a function definition from the index:
{{"action": "READ_FUNCTION", "name": "function_name"}}

3. Add a persistent security-relevant fact to Global Memory:
{{"action": "RECORD_FACT", "fact": "Description of the fact (e.g. function validateEmail() uses regex)"}}

4. Finish your analysis and output your final verdict:
{{
  "action": "FINISH",
  "vulnerable": true or false,
  "vulnerability_type": "Name or 'None'",
  "severity": "high" / "medium" / "low" / "none",
  "description": "Why it is exploitable or safe",
  "trace": "Step-by-step data flow from source to sink using the business logic",
  "recommendation": "Remediation steps"
}}

CRITICAL RULES:
- Trace the actual data flow step-by-step through the business logic.
- Look for sanitizers, type-checks, or route-level middleware validations.
- Do NOT assume sanitization exists unless you have explicitly read and verified the sanitization/validation code!
- You can make up to 5 actions/turns. Make file reads focused and small (max 50 lines) to save tokens.
- Return ONLY valid JSON, starting with {{ and ending with }}. No conversational markdown or extra text.
"""

    history.append({"role": "user", "content": system_prompt})

    max_turns = 5
    for turn in range(max_turns):
        transcript = ""
        for msg in history:
            role = "Assistant" if msg["role"] == "assistant" else "User"
            transcript += f"{role}: {msg['content']}\n\n"
        transcript += "Assistant: "

        response = detector_client.complete(transcript, max_tokens=800)
        if not response or not response.strip():
            return {
                "vulnerable": False,
                "vulnerability_type": "None",
                "severity": "none",
                "description": "Agent returned empty response.",
                "trace": "",
                "recommendation": ""
            }

        cleaned = response.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        history.append({"role": "assistant", "content": response})

        try:
            action_data = json.loads(cleaned)
        except Exception as e:
            history.append({
                "role": "user",
                "content": f"Failed to parse your response as JSON: {e}. Please respond with ONLY valid JSON."
            })
            continue

        action_name = action_data.get("action")
        if action_name == "FINISH":
            is_vuln = action_data.get("vulnerable", False)
            return {
                "vulnerable": is_vuln,
                "vulnerability_type": action_data.get("vulnerability_type", "None") if is_vuln else "None",
                "severity": action_data.get("severity", "high").lower() if is_vuln else "none",
                "description": action_data.get("description", ""),
                "trace": action_data.get("trace", ""),
                "recommendation": action_data.get("recommendation", "")
            }

        elif action_name == "READ_FILE":
            fpath = action_data.get("path")
            start = int(action_data.get("start_line", 1))
            end = int(action_data.get("end_line", 50))

            abs_path = os.path.join(target_path, fpath) if fpath else ""
            if not fpath or not os.path.isfile(abs_path):
                found = False
                if fpath:
                    for r, _, files in os.walk(target_path):
                        for file in files:
                            if file == os.path.basename(fpath):
                                abs_path = os.path.join(r, file)
                                fpath = os.path.relpath(abs_path, target_path)
                                found = True
                                break
                        if found:
                            break

            content = ""
            if fpath and os.path.isfile(abs_path):
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        content = "".join(lines[max(0, start-1):min(len(lines), end)])
                except Exception as ex:
                    content = f"Error reading file: {ex}"
            else:
                content = f"File not found: {fpath}"

            history.append({
                "role": "user",
                "content": f"Result of READ_FILE({fpath}, lines {start}-{end}):\n```\n{content}\n```"
            })
            if verbose:
                print(f"      [Agent Action] READ_FILE {fpath} (lines {start}-{end})")

        elif action_name == "READ_FUNCTION":
            fn_name = action_data.get("name")
            fn_info = None
            fpath_found = None
            if fn_boundaries:
                for fp, fns in fn_boundaries.items():
                    for f_info in fns:
                        if f_info["name"] == fn_name:
                            fn_info = f_info
                            fpath_found = fp
                            break
                    if fn_info:
                        break

            content = ""
            if fn_info and fpath_found:
                abs_path = os.path.join(target_path, fpath_found)
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        content = "".join(lines[max(0, fn_info["start"]-1):min(len(lines), fn_info["end"])])
                except Exception as ex:
                    content = f"Error reading function: {ex}"
            else:
                content = f"Function '{fn_name}' not found in IR index."

            history.append({
                "role": "user",
                "content": f"Result of READ_FUNCTION({fn_name}):\n```\n{content}\n```"
            })
            if verbose:
                print(f"      [Agent Action] READ_FUNCTION {fn_name}")

        elif action_name == "RECORD_FACT":
            fact = action_data.get("fact", "")
            global_memory.add_fact(fact)
            history.append({
                "role": "user",
                "content": f"Recorded fact to Global Memory: '{fact}'. What is your next move?"
            })
            if verbose:
                print(f"      [Agent Action] RECORD_FACT: '{fact}'")
        else:
            history.append({
                "role": "user",
                "content": f"Unknown action: '{action_name}'. Please use one of the specified actions."
            })

    force_prompt = "You have reached your turn limit. You MUST now return the final FINISH action JSON immediately."
    history.append({"role": "user", "content": force_prompt})
    transcript = ""
    for msg in history:
        role = "Assistant" if msg["role"] == "assistant" else "User"
        transcript += f"{role}: {msg['content']}\n\n"
    transcript += "Assistant: "
    response = detector_client.complete(transcript, max_tokens=600)
    try:
        cleaned = response.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()
        action_data = json.loads(cleaned)
        is_vuln = action_data.get("vulnerable", False)
        return {
            "vulnerable": is_vuln,
            "vulnerability_type": action_data.get("vulnerability_type", "None") if is_vuln else "None",
            "severity": action_data.get("severity", "high").lower() if is_vuln else "none",
            "description": action_data.get("description", ""),
            "trace": action_data.get("trace", ""),
            "recommendation": action_data.get("recommendation", "")
        }
    except Exception:
        return {
            "vulnerable": False,
            "vulnerability_type": "None",
            "severity": "none",
            "description": "Agent exceeded turn limit and failed to return valid JSON.",
            "trace": "",
            "recommendation": ""
        }


def run_consistency_reconciliation(findings, processed_flows, global_memory, detector_client, verbose=False) -> list[dict]:
    if not processed_flows:
        return findings

    flow_summaries = []
    for f in processed_flows:
        finding = next((x for x in findings if x.get("flow_id") == f["id"]), None)
        vulnerable = finding is not None
        flow_summaries.append({
            "flow_id": f["id"],
            "source": f["source"],
            "sink": f["sink"],
            "sink_type": f["sink_type"],
            "path_labels": f["path_labels"],
            "vulnerable": vulnerable,
            "severity": finding.get("severity", "none") if vulnerable else "none",
            "title": finding.get("title", "None") if vulnerable else "None",
            "description": finding.get("description", "Marked safe by detector.") if vulnerable else "Marked safe by detector."
        })

    prompt = f"""You are a security reviewer performing a quality assurance consistency check.
We analyzed several potential taint propagation flows in a codebase and made individual vulnerability decisions.
Your task is to review all decisions for contradictions or logical inconsistencies.

For example, if:
- One flow using a specific sanitizer/helper function was marked SAFE, but another flow using the same sanitizer/helper function was marked VULNERABLE.
- Two flows are virtually identical but have different verdicts.
- Safe variables (like database outputs) were incorrectly flagged as attacker-controlled.

GLOBAL METADATA:
{global_memory.to_string()}

DECISIONS MADE:
{json.dumps(flow_summaries, indent=2)}

Please output a JSON object containing the resolved findings list. If you identify any inconsistencies, correct the decision and provide a logical justification.
Your response MUST be a JSON object with this structure:
{{
  "corrections": [
    {{
      "flow_id": "flow-X",
      "original_vulnerable": true/false,
      "corrected_vulnerable": true/false,
      "reason": "Explanation of the inconsistency and why we corrected it"
    }}
  ],
  "final_verdicts": [
     {{
        "flow_id": "flow-X",
        "vulnerable": true/false,
        "vulnerability_type": "Type name or 'None'",
        "severity": "high/medium/low/none",
        "description": "Final consistent explanation",
        "recommendation": "Remediation steps"
     }}
  ]
}}

Output ONLY valid JSON. No conversational markdown, no code blocks."""

    if verbose:
        print("    [*] Running consistency reconciliation review...")

    try:
        response = detector_client.complete(prompt, max_tokens=1500)
        cleaned = response.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        data = json.loads(cleaned)
        corrections = data.get("corrections", [])
        final_verdicts = {v["flow_id"]: v for v in data.get("final_verdicts", [])}

        if corrections and verbose:
            print(f"      [Consistency Review] Applied {len(corrections)} corrections:")
            for corr in corrections:
                print(f"        - {corr['flow_id']}: vulnerable {corr['original_vulnerable']} -> {corr['corrected_vulnerable']} ({corr['reason']})")

        new_findings = []
        for f in processed_flows:
            flow_id = f["id"]
            verdict = final_verdicts.get(flow_id)
            if not verdict:
                orig_finding = next((x for x in findings if x.get("flow_id") == flow_id), None)
                if orig_finding:
                    new_findings.append(orig_finding)
                continue

            if verdict.get("vulnerable", False):
                vuln_type = verdict.get("vulnerability_type", "Potential Vulnerability")
                desc = verdict.get("description", "Vulnerability confirmed by consistency reviewer.")
                trace = verdict.get("trace", "")
                finding = {
                    "rule": vuln_type.lower().replace(" ", "-"),
                    "severity": verdict.get("severity", "high").lower(),
                    "title": vuln_type,
                    "flow_id": flow_id,
                    "description": f"{desc}\n\nTrace:\n{trace}" if trace else desc,
                    "source": f.get("source", ""),
                    "sink": f.get("sink", ""),
                    "path": f.get("path_labels", []),
                    "recommendation": verdict.get("recommendation", "Review the flow manually."),
                }
                new_findings.append(finding)

        return new_findings
    except Exception as e:
        if verbose:
            print(f"    [-] Consistency reconciliation failed: {e}")
        return findings


def run_llm_detection(repo_name, security_graph, detector_client, ir_modules=None, verbose=False) -> list[dict]:
    from cloner import repo_path

    target_path = repo_path(repo_name)
    flows = security_graph.get("flows", [])
    findings = []

    if not flows:
        if verbose:
            print("  [DEBUG] No taint flows found in security graph. LLM vulnerability detection skipped.")
        return findings

    if not detector_client:
        return findings

    node_fn_map = {}
    fn_boundaries = {}
    node_label_map = {}
    has_ir_context = bool(ir_modules)
    if ir_modules:
        node_fn_map = _build_node_fn_index(ir_modules)
        fn_boundaries = _build_function_boundaries(ir_modules)
        node_label_map = _build_node_label_map(ir_modules)

    # Global Discovery Phase to construct global context memory
    global_memory = run_llm_discovery(target_path, detector_client, ir_modules, verbose)

    total = len(flows)
    skipped = 0
    print(f"  {CYAN}[*]{RST} running agentic LLM vulnerability analysis on {total} taint flow path(s)...")

    processed_flows = []

    for flow in flows:
        flow_id = flow.get("id", "flow")
        source = flow.get("source", "")
        sink = flow.get("sink", "")
        sink_type = flow.get("sink_type", "")
        path_labels = flow.get("path_labels", [])

        # --- Pre-filter: skip trivially safe flows ---
        if _is_trivially_safe(flow):
            skipped += 1
            if verbose:
                print(f"    {DIM}[-] flow {flow_id}: skipped (trivially safe — sink: {sink}, type: {sink_type}){RST}")
            continue

        processed_flows.append(flow)

        # --- Check in-memory detector cache ---
        cache_key = _flow_cache_key(flow, getattr(detector_client, 'model', 'unknown'), getattr(detector_client, 'temperature', 0.1))
        if cache_key in _detector_cache:
            cached = _detector_cache[cache_key]
            if cached.get("vulnerable", False):
                findings.append(cached)
                print(f"    {RED}[!] cached vulnerability: {cached.get('title', 'Unknown')} ({cached.get('severity', 'high').upper()}){RST}")
            else:
                print(f"    {GRN}[+] cached flow {flow_id}: marked safe{RST}")
            continue

        # --- Run Agentic flow analysis ---
        print(f"    [*] analyzing flow {flow_id} ({source} -> {sink}) using agentic flow trace...")
        result = run_agentic_flow_analysis(
            target_path=target_path,
            flow=flow,
            node_fn_map=node_fn_map,
            fn_boundaries=fn_boundaries,
            global_memory=global_memory,
            detector_client=detector_client,
            node_label_map=node_label_map,
            verbose=verbose
        )

        is_vuln = result.get("vulnerable", False)
        if is_vuln:
            severity = result.get("severity", "high").lower()
            vuln_type = result.get("vulnerability_type", "Injection")
            desc = result.get("description", "Vulnerability found.")
            trace = result.get("trace", "")
            recommendation = result.get("recommendation", "")

            finding = {
                "rule": vuln_type.lower().replace(" ", "-"),
                "severity": severity,
                "title": vuln_type,
                "flow_id": flow_id,
                "description": f"{desc}\n\nTrace:\n{trace}",
                "source": source,
                "sink": sink,
                "path": path_labels,
                "recommendation": recommendation,
            }
            findings.append(finding)
            _detector_cache[cache_key] = finding
            print(f"    {RED}[!] confirmed vulnerability: {vuln_type} ({severity.upper()}){RST}")
        else:
            _detector_cache[cache_key] = {"vulnerable": False}
            print(f"    {GRN}[+] analyzed flow {flow_id}: marked safe (false positive or sanitised){RST}")

    if skipped:
        print(f"  {DIM}[*] skipped {skipped}/{total} trivially safe flow(s) (saved LLM calls){RST}")

    # Run consistency reconciliation on all candidate flows that passed pre-filtering
    if processed_flows:
        findings = run_consistency_reconciliation(findings, processed_flows, global_memory, detector_client, verbose)
        
        # Sync back cache to match final reconciled decisions
        for flow in processed_flows:
            flow_id = flow.get("id")
            cache_key = _flow_cache_key(flow, getattr(detector_client, 'model', 'unknown'), getattr(detector_client, 'temperature', 0.1))
            matching_finding = next((x for x in findings if x.get("flow_id") == flow_id), None)
            if matching_finding:
                _detector_cache[cache_key] = matching_finding
            else:
                _detector_cache[cache_key] = {"vulnerable": False}

    return findings


# ── Legacy snippet-based fallback (when no IR data) ────────────────────────

MAX_CODE_CHARS_PER_FILE_LEGACY = 4000
CONTEXT_LINES_LEGACY = 15

def _legacy_snippet_extract(target_path, flow, involved_files, max_chars=MAX_CODE_CHARS_PER_FILE_LEGACY):
    source_var = flow.get("source", "")
    sink_var = flow.get("sink", "")
    path_labels = flow.get("path_labels", [])

    sections = []
    for rel_file in sorted(involved_files):
        abs_file = os.path.join(target_path, rel_file)
        if not os.path.isfile(abs_file):
            continue
        try:
            with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue
        file_len = len(lines)
        if file_len == 0:
            continue

        target_lines = set()
        for i, line in enumerate(lines):
            for keyword in (source_var, sink_var):
                if keyword and keyword != "?" and keyword in line:
                    target_lines.add(i)
            for label in path_labels:
                if label and label in line:
                    target_lines.add(i)

        if target_lines:
            included = set()
            for tl in target_lines:
                start = max(0, tl - CONTEXT_LINES_LEGACY)
                end = min(file_len, tl + CONTEXT_LINES_LEGACY + 1)
                for li in range(start, end):
                    included.add(li)
            block = "\n".join(lines[li].rstrip() for li in sorted(included))
            if len(block) > max_chars:
                block = block[:max_chars] + "\n# ... (truncated)"
            sections.append(f"--- FILE: {rel_file} (relevant excerpt) ---\n{block}")
        else:
            snippet = "".join(lines[:20])
            if snippet:
                sections.append(f"--- FILE: {rel_file} (first 20 lines) ---\n{snippet}")
    return "\n\n".join(sections)


def run_llm_auth_validation(security_graph, detector_client) -> set:
    """Check unprotected routes against the LLM to filter false positives.
    Returns the set of route paths that truly need authentication.
    """
    auth = security_graph.get("subgraphs", {}).get("auth", {})
    unprotected = auth.get("unprotected", [])
    if not unprotected or not detector_client:
        return set(r["route"] if isinstance(r, dict) else r for r in unprotected)

    routes_text = "\n".join(f"  - {r['route'] if isinstance(r, dict) else r}" for r in unprotected)

    prompt = f"""You are a security expert reviewing API route paths.

For each route below, decide if it SHOULD require authentication (login).

Rules:
- Login, register, password-reset, callback pages → NO auth (they ARE the auth)
- Public assets, webhooks from third parties → NO auth
- Admin pages, dashboards, user data APIs → YES auth
- Routes that read/write user data → YES auth
- If unsure, say YES (better safe)

Reply with ONLY valid JSON:
{{"needs_auth": ["/path/one", "/path/two"], "public": ["/login"], "unsure": ["/webhook"]}}

Routes:
{routes_text}"""

    try:
        response = detector_client.complete(prompt, max_tokens=800, stream=False)
        if not response or not response.strip():
            return set(r["route"] if isinstance(r, dict) else r for r in unprotected)
        cleaned = response.strip()
        if "```" in cleaned:
            parts = cleaned.split("```")
            for p in parts:
                if p.strip().startswith("{"):
                    cleaned = p.strip()
                    if cleaned.startswith("json"):
                        cleaned = cleaned[4:]
                    break
        cleaned = cleaned.strip().strip(",")
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        data = json.loads(cleaned)
        needs = set(data.get("needs_auth", []))
        if not needs:
            needs = set(data.get("unsure", []))
        return needs
    except Exception:
        return set(r["route"] if isinstance(r, dict) else r for r in unprotected)
