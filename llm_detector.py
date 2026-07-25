import os
import json
import re
import hashlib
from colors import CYAN, GRN, YLW, RED, RST, BOLD, DIM, WHT

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
MAX_CODE_CHARS_PER_FILE = 4000
# Maximum lines of context around source/sink
CONTEXT_LINES = 15


def _flow_cache_key(flow, model_name, temperature):
    raw = f"{json.dumps(flow, sort_keys=True)}|{model_name}|{temperature}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _extract_relevant_code(target_path, flow, involved_files, max_chars=MAX_CODE_CHARS_PER_FILE):
    source_var = flow.get("source", "")
    sink_var = flow.get("sink", "")
    path_labels = flow.get("path_labels", [])

    relevant_sections = []

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

        # Find line numbers where source and sink vars appear
        target_lines = set()
        for i, line in enumerate(lines):
            for keyword in (source_var, sink_var):
                if keyword and keyword != "?" and keyword in line:
                    target_lines.add(i)
            for label in path_labels:
                if label and label in line:
                    target_lines.add(i)

        if target_lines:
            # Extract context windows around each target line
            included_lines = set()
            for tl in target_lines:
                start = max(0, tl - CONTEXT_LINES)
                end = min(file_len, tl + CONTEXT_LINES + 1)
                for li in range(start, end):
                    included_lines.add(li)

            block = "\n".join(lines[li].rstrip() for li in sorted(included_lines))
            if len(block) > max_chars:
                block = block[:max_chars] + "\n# ... (truncated)"
            relevant_sections.append(f"--- FILE: {rel_file} (relevant excerpt) ---\n{block}")
        else:
            # File is involved but no direct keyword match — include a small header
            snippet = "".join(lines[:20])
            if snippet:
                relevant_sections.append(f"--- FILE: {rel_file} (first 20 lines) ---\n{snippet}")

    return "\n\n".join(relevant_sections)


def _is_trivially_safe(flow):
    sink_type = flow.get("sink_type", "")
    sink = flow.get("sink", "")
    source = flow.get("source", "")
    path_labels = flow.get("path_labels", [])

    # If the sink is a known logging/printing function, skip
    if sink in TRIVIALLY_SAFE_SINKS or sink.split(".")[-1] in TRIVIALLY_SAFE_SINKS:
        return True

    # If the sink type is "log" or "print", skip
    if sink_type.lower() in ("log", "print", "debug"):
        return True

    # If source is from an env/config (usually safe)
    if source.startswith(TRIVIALLY_SAFE_SOURCE_PREFIXES):
        return True

    # If path is very short (source and sink are the same variable)
    if len(path_labels) <= 1:
        return True

    return False

def run_llm_detection(repo_name, security_graph, detector_client, verbose=False) -> list[dict]:
    from cloner import repo_path
    
    target_path = repo_path(repo_name)
    flows = security_graph.get("flows", [])
    findings = []
    
    if not flows:
        if verbose:
            print("  [DEBUG] No taint flows found in security graph. LLM vulnerability detection skipped.")
        return findings
        
    total = len(flows)
    skipped = 0
    print(f"  {CYAN}[*]{RST} running LLM vulnerability analysis on {total} taint flow path(s)...")
    
    for flow in flows:
        flow_id = flow.get("id", "flow")
        source = flow.get("source", "")
        sink = flow.get("sink", "")
        sink_type = flow.get("sink_type", "")
        path_labels = flow.get("path_labels", [])
        expressions = flow.get("expressions", [])

        # --- Pre-filter: skip trivially safe flows ---
        if _is_trivially_safe(flow):
            skipped += 1
            if verbose:
                print(f"    {DIM}[-] flow {flow_id}: skipped (trivially safe — sink: {sink}, type: {sink_type}){RST}")
            continue

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

        # Identify involved files
        involved_files = set()
        for step in flow.get("path", []):
            if "::" in step:
                fpath = step.split("::")[0]
                involved_files.add(fpath)
                
        # Extract only relevant code sections (reduces token usage significantly)
        files_content = _extract_relevant_code(target_path, flow, involved_files)
                        
        if not files_content:
            if verbose:
                print(f"  [DEBUG] No source code could be read for flow {flow_id}.")
            continue
            
        # Format prompt
        expr_str = "\n".join([f"  - {ex}" for ex in expressions])
        prompt = f"""You are an expert security engineer and code auditor.
We have identified a potential data-flow (taint) path in a codebase.
Determine if there is a genuine, exploitable security vulnerability.

POTENTIAL VULNERABILITY CONTEXT:
- Flow ID: {flow_id}
- Source (attacker-controlled input): {source}
- Sink (sensitive operation): {sink} (Type: {sink_type})
- Data-Flow Path Trace: {' -> '.join(path_labels)}
- Expressions/Assignments along the path:
{expr_str}

RELEVANT SOURCE CODE:
{files_content}

CRITICAL RULES:
1. Examine the source code carefully.
2. Determine if the untrusted input from the source actually reaches the sink in a way that is exploitable (e.g., SQL injection, RCE, path traversal, SSRF, auth bypass).
3. Account for any sanitization, validation, type conversions, or context checks that would make it safe.
4. Output only valid JSON with no markdown blocks or extra text.

Expected JSON:
{{
  "vulnerable": true or false,
  "vulnerability_type": "Vulnerability Type Name",
  "severity": "high", "medium", or "low",
  "description": "Clear explanation of the vulnerability and why it is exploitable.",
  "trace": "Detailed trace explaining how the input moves from source to sink in the code.",
  "recommendation": "Specific remediation steps to fix the issue."
}}"""

        is_verbose = verbose or os.environ.get("ULTRON_DEBUG") == "1"
        if is_verbose:
            print(f"\n{CYAN}==================== [DEBUG LLM DETECTOR INPUT: {flow_id}] ===================={RST}")
            print(prompt)
            print(f"{CYAN}============================================================================={RST}")

        # Retry up to 2 times on unparseable JSON
        max_json_retries = 2
        last_response = ""
        last_error = None
        response = ""

        for attempt in range(max_json_retries + 1):
            print(f"    [*] analyzing flow {flow_id} ({source} -> {sink}) using model '{detector_client.model}'...")
            response = detector_client.complete(prompt, max_tokens=1000, stream=True)

            if is_verbose:
                if response:
                    print(f"\n{GRN}===== LLM RESPONSE [{flow_id}] (attempt {attempt+1}) ====={RST}")
                    print(response[:2000])
                    print(f"{GRN}==================================={RST}\n")
                else:
                    print(f"\n{YLW}===== LLM RESPONSE [{flow_id}] (attempt {attempt+1}) EMPTY ====={RST}\n")

            if not response or not response.strip():
                last_error = "empty response"
                if attempt < max_json_retries:
                    if is_verbose:
                        print(f"  {YLW}[!] empty response, retrying...{RST}")
                    continue
                _detector_cache[cache_key] = {"vulnerable": False}
                print(f"    {YLW}[?] flow {flow_id}: no response from LLM (empty){RST}")
                break

            try:
                cleaned_resp = response.strip()
                if cleaned_resp.startswith("```json"):
                    cleaned_resp = cleaned_resp[7:]
                if cleaned_resp.startswith("```"):
                    cleaned_resp = cleaned_resp[3:]
                if cleaned_resp.endswith("```"):
                    cleaned_resp = cleaned_resp[:-3]
                cleaned_resp = cleaned_resp.strip()

                data = json.loads(cleaned_resp)
                if data.get("vulnerable", False):
                    severity = data.get("severity", "high").lower()
                    vuln_type = data.get("vulnerability_type", "Injection")
                    desc = data.get("description", "Vulnerability found.")
                    trace = data.get("trace", "")
                    recommendation = data.get("recommendation", "")

                    finding = {
                        "rule": vuln_type.lower().replace(" ", "-"),
                        "severity": severity,
                        "title": vuln_type,
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
                break
            except Exception as e:
                last_error = f"JSON parse error: {e}"
                if attempt < max_json_retries:
                    if is_verbose:
                        print(f"  {YLW}[!] {last_error}, retrying with stricter prompt...{RST}")
                    # Retry with stronger JSON instruction
                    prompt += "\n\nIMPORTANT: You MUST output valid JSON only. No markdown, no explanation, no code blocks. Start with { and end with }."
                    continue
                # Out of retries
                if is_verbose:
                    print(f"  {RED}[DEBUG] {last_error}{RST}")
                if '"vulnerable": true' in response.lower() or '"vulnerable":true' in response.lower():
                    finding = {
                        "rule": "potential-vulnerability",
                        "severity": "high",
                        "title": "Potential Vulnerability",
                        "description": f"The model flagged this flow as vulnerable, but failed to output valid JSON after retries. Raw response:\n{response}",
                        "source": source,
                        "sink": sink,
                        "path": path_labels,
                        "recommendation": "Review the flow manually for security flaws.",
                    }
                    findings.append(finding)
                    _detector_cache[cache_key] = finding
                    print(f"    {RED}[!] flagged potential vulnerability (raw response mentioned 'vulnerable: true'){RST}")
                else:
                    _detector_cache[cache_key] = {"vulnerable": False}
                    if is_verbose:
                        print(f"    {YLW}[?] flow {flow_id}: {last_error}. Raw response:{RST}")
                        print(f"    {DIM}{response[:500] if response else '(empty)'}{RST}")
                    print(f"    {YLW}[?] flow {flow_id}: marked safe (unparseable after {max_json_retries+1} attempts){RST}")
                break
                
    if skipped:
        print(f"  {DIM}[*] skipped {skipped}/{total} trivially safe flow(s) (saved LLM calls){RST}")
                
    return findings
