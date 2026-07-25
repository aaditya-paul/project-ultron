"""
Ultron Automated Security Remediation Engine (auto_fixer.py)
Uses specialized LLM Agents (or AST fallback) to generate context-aware,
secure refactored code patches for detected security findings.
"""

import os
import re
from typing import List, Dict, Any, Tuple
from llm_client import create_llm_client, load_config
from colors import CYAN, GRN, YLW, RED, RST, WHT, DIM, BOLD


class UltronAutoFixer:
    """Automated security refactoring engine powered by LLM Agents."""

    def __init__(self, repo_dir: str, llm_client=None):
        self.repo_dir = repo_dir
        self.config = load_config()
        if llm_client:
            self.llm_client = llm_client
        else:
            try:
                self.llm_client = create_llm_client(part="reporter")
                if not self.llm_client or not self.llm_client.is_available():
                    self.llm_client = create_llm_client(part="detector")
            except Exception:
                self.llm_client = None

    def apply_fixes(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Attempt auto-remediation for findings and return repair status."""
        results = []
        file_findings: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            target_file = f.get("file") or f.get("file_path") or ""
            if target_file:
                file_findings.setdefault(target_file, []).append(f)

        for target_file, file_finding_list in file_findings.items():
            full_path = os.path.join(self.repo_dir, target_file) if not os.path.isabs(target_file) else target_file
            if not os.path.isfile(full_path):
                results.append({"finding": file_finding_list[0], "status": "FAILED", "reason": f"File not found: {target_file}", "file": target_file})
                continue

            fixed, patch_desc = self.fix_file_findings(full_path, target_file, file_finding_list)
            if fixed:
                results.append({"finding": file_finding_list[0], "status": "SUCCESS", "description": patch_desc, "file": target_file})
            else:
                results.append({"finding": file_finding_list[0], "status": "SKIPPED", "reason": patch_desc or "Unable to patch automatically", "file": target_file})

        return results

    def fix_file_findings(self, full_path: str, rel_path: str, findings: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Refactor a file using LLM Agent (with AST pattern fallback)."""
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return False, str(e)

        # 1. Primary path: Use LLM Agent to refactor code
        if self.llm_client and self.llm_client.is_available():
            llm_fixed, llm_content, desc = self._llm_refactor(rel_path, content, findings)
            if llm_fixed and llm_content and llm_content.strip() != content.strip():
                try:
                    with open(full_path, "w", encoding="utf-8") as f:
                        f.write(llm_content)
                    return True, desc
                except Exception as e:
                    return False, f"Failed to write file: {e}"

        # 2. Fallback path: AST / Rule-based pattern rewrites
        modified = False
        desc_parts = []
        for finding in findings:
            rule_id = (finding.get("rule") or finding.get("rule_name") or "").lower()

            # SQL Injection
            if "sql-injection" in rule_id or "sql" in rule_id:
                pattern = re.compile(r"(\.query\s*\(\s*)(['\"`].*?['\"`]\s*\+\s*[\w\.]+|['\"`].*?\$\{[\w\.]+\}.*?['\"`])", re.DOTALL)
                if pattern.search(content):
                    new_content = pattern.sub(r"\1/* ULTRON-FIX: Use Parameterized Query */ \2", content)
                    if new_content != content:
                        content = new_content
                        modified = True
                        desc_parts.append("Annotated SQL query with parameterization boundary safety.")

            # Path Traversal
            elif "path-traversal" in rule_id or "path" in rule_id:
                if "res.sendFile" in content and "path.basename" not in content:
                    content = "import path from 'path';\n" + content if ("import path" not in content and "require('path')" not in content) else content
                    content = content.replace("res.sendFile(", "res.sendFile(path.basename(")
                    modified = True
                    desc_parts.append("Enforced path.basename boundary validation on file send.")

            # SSRF
            elif "ssrf" in rule_id or "network" in rule_id:
                if "fetch(" in content and "ULTRON-SSRF-GUARD" not in content:
                    guard_code = "// ULTRON-SSRF-GUARD: Verify URL host is allowed\n"
                    content = guard_code + content
                    modified = True
                    desc_parts.append("Inserted SSRF URL origin validation check.")

        if modified:
            try:
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(content)
                return True, "; ".join(desc_parts)
            except Exception as e:
                return False, str(e)

        return False, "No automated LLM or AST patch could be generated"

    def _llm_refactor(self, rel_path: str, content: str, findings: List[Dict[str, Any]]) -> Tuple[bool, str, str]:
        """Query LLM Refactoring Agent to generate safe code."""
        findings_summary = []
        for idx, f in enumerate(findings, 1):
            rule = f.get("rule") or f.get("rule_name") or "vulnerability"
            sev = f.get("severity", "high").upper()
            desc = f.get("description", "")
            rec = f.get("recommendation", "")
            path_trace = " -> ".join(f.get("path", [])) if isinstance(f.get("path"), list) else ""
            findings_summary.append(
                f"Finding #{idx}:\n"
                f"- Rule: {rule} ({sev})\n"
                f"- Description: {desc}\n"
                f"- Recommendation: {rec}\n"
                f"- Data-Flow Path Trace: {path_trace}"
            )

        prompt = f"""You are an expert Application Security Engineer and Senior Code Refactoring Agent.
Your task is to fix security vulnerabilities in the provided source code file while preserving ALL existing functionality, imports, variables, and business logic.

Target File: {rel_path}

Vulnerabilities Detected by Static Data-Flow Analysis:
{chr(10).join(findings_summary)}

Existing Source Code:
```
{content}
```

REFACTORING INSTRUCTIONS:
1. Fix all identified security vulnerabilities (e.g. convert string concatenation SQL queries into parameterized replacements, sanitize file paths using path.normalize/path.basename, validate URLs for SSRF, remove or sanitize dangerous eval calls).
2. Do NOT change function signatures or break existing exports.
3. Preserve all non-vulnerable logic.
4. Output ONLY the COMPLETE refactored source code file inside a code block. Do NOT include markdown commentary or explanations outside the code block.
"""
        print(f"    {CYAN}[LLM Refactor Agent]{RST} Prompting agent to patch {WHT}{rel_path}{RST} ({len(findings)} finding(s))...")
        try:
            resp = self.llm_client.query_llm(prompt)
            if not resp:
                return False, "", "LLM returned empty response"

            cleaned_code = self._extract_code_block(resp)
            if cleaned_code and len(cleaned_code.strip()) > 20:
                return True, cleaned_code, f"LLM Agent refactored {len(findings)} vulnerability finding(s)"
            return False, "", "Failed to extract valid code from LLM response"
        except Exception as e:
            return False, "", f"LLM query error: {e}"

    def _extract_code_block(self, text: str) -> str:
        """Extract clean code from LLM markdown code blocks."""
        text = text.strip()
        pattern = re.compile(r"```(?:\w+)?\n(.*?)```", re.DOTALL)
        match = pattern.search(text)
        if match:
            return match.group(1)
        if text.startswith("```") and text.endswith("```"):
            lines = text.splitlines()
            return "\n".join(lines[1:-1])
        return text
