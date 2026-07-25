import fnmatch
import re
import os
import json
from dataclasses import asdict
from typing import Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from features import FunctionFeatures
from colors import CYAN, GRN, RST, YLW, DIM, RED, WHT


SOURCE_PARAMS = {"req", "request", "payload", "body", "query", "params", "event"}
SOURCE_FIELDS = {"*.body", "*.query", "*.params", "*.body.*", "*.query.*", "*.params.*"}

SINK_DB_PATTERNS = {
    "*db.*", "*query*", "*insert*", "*update*", "*delete*", "*upsert*", "*execute*",
    "*prisma*", "*knex*", "*mongoose*", "*sequelize*", "*find*", "*save*", "*select*",
    "*join*", "*where*", "*orderby*", "*groupby*"
}

SINK_SHELL_PATTERNS = {
    "*exec*", "*spawn*", "*child_process*", "*shell*", "*system*", "*popen*", "*execsync*"
}

SINK_FILE_PATTERNS = {
    "*readfile*", "*writefile*", "*openfile*", "*unlink*", "*readdir*", "*fs.*", "*file.*", "*stream*"
}

SINK_NETWORK_PATTERNS = {
    "*fetch*", "*axios*", "*request*", "*ajax*", "*http.*", "*https.*", "*got*", "*superagent*"
}

AUTH_PATTERNS = {
    "*auth*", "*login*", "*signin*", "*signup*", "*logout*", "*verifytoken*", "*authenticate*",
    "*authorize*", "*middleware*", "*guard*", "*jwt*", "*signtoken*", "*secret*", "*password*",
    "*key*", "*credential*"
}

VALIDATION_PATTERNS = {
    "*validate*", "*sanitize*", "*escape*", "*assert*", "*zod*", "*yup*", "*joi*"
}

ROUTE_PATTERNS = {
    "*handler*", "*route*", "*controller*", "*api*", "*router*", "*get*", "*post*", "*put*", "*patch*", "*delete*"
}

def matches_any_glob(text: str, patterns: set) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    for pat in patterns:
        if fnmatch.fnmatch(text_lower, pat.lower()):
            return True
    return False

class Classification:
    def __init__(self, label: str, confidence: float, by: str):
        self.label = label
        self.confidence = confidence
        self.by = by

    def to_dict(self):
        return {
            "label": self.label,
            "confidence": self.confidence,
            "by": self.by
        }

class PatternPass:
    def classify(self, features: FunctionFeatures) -> Optional[Classification]:
        debug = os.environ.get("ULTRON_DEBUG") == "1"
        
        # Check params against known source names
        for p in features.params:
            if p.lower() in SOURCE_PARAMS:
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SOURCE (param '{p}' in SOURCE_PARAMS){RST}")
                return Classification("SOURCE", confidence=0.85, by="pattern")
            
        # Check field accesses for source patterns
        for fa in features.field_accesses:
            if matches_any_glob(fa, SOURCE_FIELDS):
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SOURCE (field access '{fa}' matches SOURCE_FIELDS){RST}")
                return Classification("SOURCE", confidence=0.90, by="pattern")

        # Check calls against known sink patterns
        for call in features.calls_made:
            if matches_any_glob(call, SINK_SHELL_PATTERNS):
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SINK_SHELL (call '{call}' matches SINK_SHELL_PATTERNS){RST}")
                return Classification("SINK_SHELL", confidence=0.90, by="pattern")
            if matches_any_glob(call, SINK_DB_PATTERNS):
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SINK_DATABASE (call '{call}' matches SINK_DB_PATTERNS){RST}")
                return Classification("SINK_DATABASE", confidence=0.85, by="pattern")
            if matches_any_glob(call, SINK_FILE_PATTERNS):
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SINK_FILE (call '{call}' matches SINK_FILE_PATTERNS){RST}")
                return Classification("SINK_FILE", confidence=0.85, by="pattern")
            if matches_any_glob(call, SINK_NETWORK_PATTERNS):
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SINK_NETWORK (call '{call}' matches SINK_NETWORK_PATTERNS){RST}")
                return Classification("SINK_NETWORK", confidence=0.85, by="pattern")
            if matches_any_glob(call, AUTH_PATTERNS):
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> AUTH (call '{call}' matches AUTH_PATTERNS){RST}")
                return Classification("AUTH", confidence=0.85, by="pattern")
            if matches_any_glob(call, VALIDATION_PATTERNS):
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> VALIDATION (call '{call}' matches VALIDATION_PATTERNS){RST}")
                return Classification("VALIDATION", confidence=0.85, by="pattern")
            if matches_any_glob(call, ROUTE_PATTERNS):
                if debug:
                    print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> ROUTE (call '{call}' matches ROUTE_PATTERNS){RST}")
                return Classification("ROUTE", confidence=0.80, by="pattern")
                
        # Also check function name as fallback
        name_low = features.name.lower()
        if matches_any_glob(name_low, SINK_SHELL_PATTERNS):
            if debug:
                print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SINK_SHELL (name '{features.name}' matches SINK_SHELL_PATTERNS){RST}")
            return Classification("SINK_SHELL", confidence=0.75, by="pattern")
        if matches_any_glob(name_low, SINK_DB_PATTERNS):
            if debug:
                print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SINK_DATABASE (name '{features.name}' matches SINK_DB_PATTERNS){RST}")
            return Classification("SINK_DATABASE", confidence=0.75, by="pattern")
        if matches_any_glob(name_low, SINK_FILE_PATTERNS):
            if debug:
                print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SINK_FILE (name '{features.name}' matches SINK_FILE_PATTERNS){RST}")
            return Classification("SINK_FILE", confidence=0.75, by="pattern")
        if matches_any_glob(name_low, SINK_NETWORK_PATTERNS):
            if debug:
                print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> SINK_NETWORK (name '{features.name}' matches SINK_NETWORK_PATTERNS){RST}")
            return Classification("SINK_NETWORK", confidence=0.75, by="pattern")
        if matches_any_glob(name_low, AUTH_PATTERNS):
            if debug:
                print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> AUTH (name '{features.name}' matches AUTH_PATTERNS){RST}")
            return Classification("AUTH", confidence=0.75, by="pattern")
        if matches_any_glob(name_low, VALIDATION_PATTERNS):
            if debug:
                print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> VALIDATION (name '{features.name}' matches VALIDATION_PATTERNS){RST}")
            return Classification("VALIDATION", confidence=0.75, by="pattern")
        if matches_any_glob(name_low, ROUTE_PATTERNS):
            if debug:
                print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> ROUTE (name '{features.name}' matches ROUTE_PATTERNS){RST}")
            return Classification("ROUTE", confidence=0.70, by="pattern")

        if debug:
            print(f"  {DIM}[DEBUG] PatternPass: '{features.name}' -> No pattern matched (sending to LLM if available){RST}")
        return None

def parse_response(response_text: str) -> Tuple[str, float]:
    valid_labels = {"SOURCE", "SINK_DATABASE", "SINK_SHELL", "SINK_FILE", "SINK_NETWORK", "AUTH", "VALIDATION", "ROUTE", "NONE"}
    
    # Try parsing XML tags first
    class_match = re.search(r'<classification>\s*([A-Z_]+)\s*</classification>', response_text, re.IGNORECASE)
    conf_match = re.search(r'<confidence>\s*([\d.]+)\s*</confidence>', response_text)
    
    detected_label = None
    confidence = 0.80
    
    if class_match:
        val = class_match.group(1).upper().strip()
        if val in valid_labels:
            detected_label = val
            
    if conf_match:
        try:
            val = float(conf_match.group(1).strip())
            if 0.0 <= val <= 1.0:
                confidence = val
        except ValueError:
            pass
            
    # Fallback to the old word-matching logic if XML tags are missing
    if not detected_label:
        cleaned = re.sub(r'[*`#,()]', ' ', response_text).strip()
        for word in cleaned.split():
            word_upper = word.upper().strip()
            if word_upper in valid_labels:
                detected_label = word_upper
                break
                
        if not detected_label:
            cleaned_upper = cleaned.upper()
            for label in valid_labels:
                if label in cleaned_upper:
                    detected_label = label
                    break
                    
        if not detected_label:
            detected_label = "NONE"
            
        # Extract confidence from words
        floats = re.findall(r'\b\d+(?:\.\d+)?\b', cleaned)
        for val in floats:
            try:
                f = float(val)
                if 0.0 <= f <= 1.0:
                    confidence = f
                    break
            except ValueError:
                pass
                
    if os.environ.get("ULTRON_DEBUG") == "1":
        print(f"  {DIM}[DEBUG] parse_response: parsed raw response to label: '{detected_label}', confidence: {confidence}{RST}")
        
    return detected_label, confidence

ROLE_DESCRIPTIONS = """- SOURCE: receives attacker-controlled input (HTTP req/res, event payloads, user-supplied data)
- SINK_DATABASE: writes to or queries a database (query, execute, find, save, insert, update, delete, ORM)
- SINK_SHELL: executes system/shell commands (exec, spawn, system, popen, child_process)
- SINK_FILE: reads/writes/deletes files on the filesystem
- SINK_NETWORK: makes outbound network requests (fetch, axios, http.request, got)
- AUTH: authentication, authorization, token checks, login, JWT, access control
- VALIDATION: validates, sanitizes, escapes, or parses inputs (zod, joi, yup, assert)
- ROUTE: HTTP endpoint handler (GET/POST route handlers, API controllers)
- NONE: not security-relevant (utility, helper, logger, UI component)"""

BATCH_PROMPT_TEMPLATE = """You are a security code analyzer. Classify each function below into exactly one security role.

Available roles:
{role_descriptions}

Return ONLY a valid JSON array. No markdown, no explanation, no extra text.
Format: [{{"name": "...", "classification": "...", "confidence": 0.0-1.0}}]

Functions:
{functions_json}"""

class LLMPass:
    PROMPT_TEMPLATE = """<|think|> You are a security code analyzer. Given a function's features, classify its security role.

FUNCTION: {name}
FILE: {file_path}
PARAMS: {params}
BODY:
{body_text}

CALLS MADE: {calls_made}
IMPORTS IN FILE: {file_imports}
CALLED BY: {calls_to_this}

Classify this function as exactly ONE of these security roles:
{role_descriptions}

Provide your reasoning, then output the final classification and confidence score enclosed in XML tags.
Format:
<classification>ROLE</classification>
<confidence>SCORE</confidence>

Example:
<classification>SINK_DATABASE</classification>
<confidence>0.85</confidence>"""

    def __init__(self, llm_client):
        self.llm_client = llm_client

    def classify(self, features: FunctionFeatures) -> Classification:
        prompt = self.PROMPT_TEMPLATE.format(
            name=features.name,
            file_path=features.file_path,
            params=features.params,
            body_text=features.body_text,
            calls_made=features.calls_made,
            file_imports=features.file_imports,
            calls_to_this=features.calls_to_this,
            role_descriptions=ROLE_DESCRIPTIONS
        )
        if os.environ.get("ULTRON_DEBUG") == "1":
            print(f"\n{CYAN}==================== [DEBUG LLM INPUT: {features.name}] ===================={RST}")
            print(prompt)
            print(f"{CYAN}========================================================================{RST}")
        response = self.llm_client.complete(prompt, max_tokens=1024, stream=True)
        if os.environ.get("ULTRON_DEBUG") == "1":
            print(f"{GRN}========================================================================{RST}\n")
        label, confidence = parse_response(response)
        return Classification(label, confidence, by="llm")

    def _format_single_features(self, feat: FunctionFeatures) -> dict:
        return {
            "name": feat.name or "<anonymous>",
            "file": feat.file_path,
            "params": feat.params,
            "calls": feat.calls_made[:15],
            "imports": feat.file_imports[:8],
            "body": (feat.body_text or "")[:500]
        }

    def _parse_batch_response(self, raw: str, total: int) -> List[Optional[Classification]]:
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            data = json.loads(cleaned)
            if len(data) != total:
                return []
            results = []
            for entry in data:
                label = entry.get("classification", "NONE")
                conf = float(entry.get("confidence", 0.8))
                results.append(Classification(label, min(conf, 1.0), by="llm"))
            return results
        except Exception:
            return []

    def classify_batch(self, features_list: List[FunctionFeatures]) -> List[Classification]:
        total = len(features_list)
        verbose = os.environ.get("ULTRON_DEBUG") == "1"

        if total == 0:
            return []

        results: List[Optional[Classification]] = [None] * total

        if total > 5:
            BATCH_SIZE = 10
            batches = [features_list[i:i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]

            for batch in batches:
                batch_total = len(batch)
                funcs_json = json.dumps([
                    self._format_single_features(f) for f in batch
                ], indent=2)
                prompt = BATCH_PROMPT_TEMPLATE.format(
                    role_descriptions=ROLE_DESCRIPTIONS,
                    functions_json=funcs_json
                )

                if verbose:
                    print(f"\n{CYAN}==================== [BATCH LLM: {batch_total} functions] ===================={RST}")

                response = self.llm_client.complete(prompt, max_tokens=4096)

                if verbose:
                    print(f"{CYAN}====================================================================={RST}\n")

                batch_results = self._parse_batch_response(response, batch_total)
                if len(batch_results) == batch_total:
                    for feat, res in zip(batch, batch_results):
                        idx = features_list.index(feat)
                        results[idx] = res
                    if verbose:
                        for i, (feat, res) in enumerate(zip(batch, batch_results)):
                            name = feat.name or "<anonymous>"
                            print(f"  {GRN}[+]{RST} classified {WHT}{name}{RST} -> {res.label} ({i+1}/{batch_total})")
                else:
                    if verbose:
                        print(f"  {YLW}[!]{RST} batch JSON parse failed, falling back to individual calls")
                    for feat in batch:
                        idx = features_list.index(feat)
                        results[idx] = self._classify_single(feat, verbose)

            return results

        for feat in features_list:
            idx = features_list.index(feat)
            results[idx] = self._classify_single(feat, verbose)

        return results

    def _classify_single(self, feat: FunctionFeatures, verbose: bool) -> Classification:
        prompt = self.PROMPT_TEMPLATE.format(
            name=feat.name or "<anonymous>",
            file_path=feat.file_path,
            params=feat.params,
            body_text=feat.body_text,
            calls_made=feat.calls_made,
            file_imports=feat.file_imports,
            calls_to_this=feat.calls_to_this,
            role_descriptions=ROLE_DESCRIPTIONS
        )
        if verbose:
            print(f"\n{CYAN}==================== [DEBUG LLM INPUT: {feat.name}] ===================={RST}")
            print(prompt)
            print(f"{CYAN}========================================================================{RST}")
        response = self.llm_client.complete(prompt, max_tokens=1024, stream=True)
        if verbose:
            print(f"{GRN}========================================================================{RST}\n")
        label, confidence = parse_response(response)
        return Classification(label, confidence, by="llm")

class HybridClassifier:
    def __init__(self, llm_client=None):
        self.pattern_pass = PatternPass()
        self.llm_pass = LLMPass(llm_client) if llm_client else None
        self.stats = {
            "pattern_classified": 0,
            "llm_classified": 0,
            "unclassified": 0,
        }

    def classify_all(self, all_features: List[FunctionFeatures]) -> List[Tuple[FunctionFeatures, Classification]]:
        results = []
        unclassified = []
        
        self.stats = {
            "pattern_classified": 0,
            "llm_classified": 0,
            "unclassified": 0,
        }

        # Pass 1: patterns (instant)
        for feat in all_features:
            res = self.pattern_pass.classify(feat)
            if res:
                results.append((feat, res))
                self.stats["pattern_classified"] += 1
            else:
                unclassified.append(feat)

        # Pass 2: LLM (batched)
        if self.llm_pass and unclassified:
            llm_results = self.llm_pass.classify_batch(unclassified)
            for feat, res in zip(unclassified, llm_results):
                results.append((feat, res))
                self.stats["llm_classified"] += 1
        else:
            for feat in unclassified:
                # Fallback to NONE if no LLM is running
                results.append((feat, Classification("NONE", 0.0, "none")))
                self.stats["unclassified"] += 1
                
        return results
