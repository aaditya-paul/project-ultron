import os
import json
import re
from colors import CYAN, GRN, YLW, RED, RST, BOLD, DIM, WHT

def run_llm_detection(repo_name, security_graph, detector_client, verbose=False) -> list[dict]:
    from cloner import repo_path
    
    target_path = repo_path(repo_name)
    flows = security_graph.get("flows", [])
    findings = []
    
    if not flows:
        if verbose:
            print("  [DEBUG] No taint flows found in security graph. LLM vulnerability detection skipped.")
        return findings
        
    print(f"  {CYAN}[*]{RST} running LLM vulnerability analysis on {len(flows)} taint flow path(s)...")
    
    for flow in flows:
        flow_id = flow.get("id", "flow")
        source = flow.get("source", "")
        sink = flow.get("sink", "")
        sink_type = flow.get("sink_type", "")
        path_labels = flow.get("path_labels", [])
        expressions = flow.get("expressions", [])
        
        # Identify involved files
        involved_files = set()
        for step in flow.get("path", []):
            if "::" in step:
                fpath = step.split("::")[0]
                involved_files.add(fpath)
                
        # Read the file contents
        files_content = ""
        for rel_file in sorted(involved_files):
            abs_file = os.path.join(target_path, rel_file)
            if os.path.isfile(abs_file):
                try:
                    with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    files_content += f"\n--- FILE: {rel_file} ---\n{content}\n"
                except Exception as e:
                    if verbose:
                        print(f"  [DEBUG] Failed to read {rel_file}: {e}")
                        
        if not files_content:
            if verbose:
                print(f"  [DEBUG] No source code could be read for flow {flow_id}.")
            continue
            
        # Format prompt
        expr_str = "\n".join([f"  - {ex}" for ex in expressions])
        prompt = f"""<|think|> You are an expert security engineer and code auditor.
We have identified a potential data-flow (taint) path in a codebase.
Your task is to analyze the source code of the involved files and determine if there is a genuine, exploitable security vulnerability.

POTENTIAL VULNERABILITY CONTEXT:
- Flow ID: {flow_id}
- Source (attacker-controlled input): {source}
- Sink (sensitive operation): {sink} (Type: {sink_type})
- Data-Flow Path Trace: {' -> '.join(path_labels)}
- Expressions/Assignments along the path:
{expr_str}

INVOLVED FILES SOURCE CODE:
{files_content}

CRITICAL RULES:
1. Examine the source code of the involved files carefully.
2. Determine if the untrusted input from the source actually reaches the sink in a way that is exploitable (e.g., SQL injection, Remote Code Execution, path traversal, SSRF, auth bypass, etc.).
3. Account for any sanitization, validation, type conversions, or context checks that would make it safe.
4. Output your analysis and decision in the following JSON format. Do not output any other text or markdown block outside the JSON.

Expected JSON output format:
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

        print(f"    [*] analyzing flow {flow_id} ({source} -> {sink}) using model '{detector_client.model}'...")
        response = detector_client.complete(prompt, max_tokens=1000, stream=True)

        if is_verbose:
            print(f"{GRN}============================================================================={RST}\n")
            
        # Parse JSON response
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
                
                findings.append({
                    "rule": vuln_type.lower().replace(" ", "-"),
                    "severity": severity,
                    "title": vuln_type,
                    "description": f"{desc}\n\nTrace:\n{trace}",
                    "source": source,
                    "sink": sink,
                    "path": path_labels,
                    "recommendation": recommendation,
                })
                print(f"    {RED}[!] confirmed vulnerability: {vuln_type} ({severity.upper()}){RST}")
            else:
                print(f"    {GRN}[+] analyzed flow {flow_id}: marked safe (false positive or sanitised){RST}")
        except Exception as e:
            if verbose or os.environ.get("ULTRON_DEBUG") == "1":
                print(f"  [DEBUG] Failed to parse JSON response from detector LLM: {e}")
            # If JSON parsing fails, let's try a fallback: does it say vulnerable: true?
            if '"vulnerable": true' in response.lower() or '"vulnerable":true' in response.lower():
                findings.append({
                    "rule": "potential-vulnerability",
                    "severity": "high",
                    "title": "Potential Vulnerability",
                    "description": f"The model flagged this flow as vulnerable, but failed to output valid JSON. Raw response:\n{response}",
                    "source": source,
                    "sink": sink,
                    "path": path_labels,
                    "recommendation": "Review the flow manually for security flaws.",
                })
                print(f"    {RED}[!] flagged potential vulnerability (failed to parse JSON response){RST}")
            else:
                print(f"    {GRN}[+] analyzed flow {flow_id}: marked safe (or failed to parse response){RST}")
                
    return findings
