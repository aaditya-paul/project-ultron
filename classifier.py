import fnmatch
import re
import os
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
- SOURCE: receives attacker-controlled input. This includes any function accepting HTTP requests, req/res objects, event payloads, webhook inputs, or parameters representing user-supplied data.
- SINK_DATABASE: writes to, queries, or interacts with a database (SQL, NoSQL, ORMs). E.g., calls to query(), execute(), find(), save(), insert(), update(), delete(), or ORM methods.
- SINK_SHELL: executes system or shell commands. E.g., spawn(), exec(), system(), popen(), child_process.
- SINK_FILE: reads, writes, deletes, or manipulates files on the local filesystem.
- SINK_NETWORK: makes outbound network requests (fetch, axios, http/https requests, request, got).
- AUTH: performs authentication, authorization, token checks, logins, sign-ins, JWT signing/verification, permission validation, or access control checks.
- VALIDATION: validates, sanitizes, escapes, checks, or parses inputs to ensure safety (e.g. zod parse, joi, yup, escape, sanitize, assert).
- ROUTE: is an HTTP endpoint handler (e.g. GET/POST route handlers, API controllers, router methods).
- NONE: not security-relevant. Use this if the function is a pure utility, helper, logger, UI component, or has no security significance.

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
            calls_to_this=features.calls_to_this
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

    def classify_batch(self, features_list: List[FunctionFeatures]) -> List[Classification]:
        prompts = [
            self.PROMPT_TEMPLATE.format(
                name=feat.name,
                file_path=feat.file_path,
                params=feat.params,
                body_text=feat.body_text,
                calls_made=feat.calls_made,
                file_imports=feat.file_imports,
                calls_to_this=feat.calls_to_this
            )
            for feat in features_list
        ]
        total = len(features_list)
        verbose = os.environ.get("ULTRON_DEBUG") == "1"

        results = [None] * total
        completed = 0

        with ThreadPoolExecutor(max_workers=self.llm_client.num_workers) as executor:
            future_map = {
                executor.submit(self.llm_client.complete, prompts[i], 1024): i
                for i in range(total)
            }
            for future in as_completed(future_map):
                idx = future_map[future]
                resp = future.result()
                label, confidence = parse_response(resp)
                results[idx] = Classification(label, confidence, by="llm")
                completed += 1
                if verbose:
                    name = features_list[idx].name or "<anonymous>"
                    print(f"  {GRN}[+]{RST} classified {WHT}{name}{RST} ({completed}/{total})")

        return results

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
