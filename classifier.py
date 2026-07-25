import fnmatch
import re
import os
from dataclasses import asdict
from typing import Optional, List, Tuple
from features import FunctionFeatures
from colors import CYAN, GRN, RST, YLW, DIM, RED


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
    
    # Clean up text (do not strip underscores, as they are part of labels like SINK_DATABASE)
    cleaned = re.sub(r'[*`#,()]', ' ', response_text).strip()
    
    detected_label = "NONE"
    for word in cleaned.split():
        word_upper = word.upper().strip()
        if word_upper in valid_labels:
            detected_label = word_upper
            break
            
    if detected_label == "NONE":
        cleaned_upper = cleaned.upper()
        for label in valid_labels:
            if label in cleaned_upper:
                detected_label = label
                break
                
    confidence = 0.80
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
    PROMPT_TEMPLATE = """You are a security code analyzer. Given a function's features, classify its security role.

FUNCTION: {name}
FILE: {file_path}
PARAMS: {params}
BODY:
{body_text}

CALLS MADE: {calls_made}
IMPORTS IN FILE: {file_imports}
CALLED BY: {calls_to_this}

Classify this function as exactly ONE of:
- SOURCE: receives attacker-controlled input (HTTP request data, user input, URL params)
- SINK_DATABASE: writes to or queries a database
- SINK_SHELL: executes system commands
- SINK_FILE: reads/writes files with potentially untrusted paths
- SINK_NETWORK: makes outbound HTTP/network requests
- AUTH: performs authentication or authorization checks
- VALIDATION: validates or sanitizes input
- ROUTE: HTTP endpoint handler
- NONE: not security-relevant

Respond with ONLY the classification and a confidence score 0.0-1.0.
Format: CLASSIFICATION confidence
Example: SINK_DATABASE 0.85"""

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
        response = self.llm_client.complete(prompt)
        if os.environ.get("ULTRON_DEBUG") == "1":
            print(f"{GRN}==================== [DEBUG LLM OUTPUT: {features.name}] ===================={RST}")
            print(response)
            print(f"{GRN}========================================================================={RST}\n")
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
        if os.environ.get("ULTRON_DEBUG") == "1":
            for feat, prompt in zip(features_list, prompts):
                print(f"\n{CYAN}==================== [DEBUG LLM INPUT: {feat.name}] ===================={RST}")
                print(prompt)
                print(f"{CYAN}========================================================================{RST}")
        responses = self.llm_client.batch_complete(prompts)
        results = []
        for feat, resp in zip(features_list, responses):
            if os.environ.get("ULTRON_DEBUG") == "1":
                print(f"{GRN}==================== [DEBUG LLM OUTPUT: {feat.name}] ===================={RST}")
                print(resp)
                print(f"{GRN}========================================================================={RST}\n")
            label, confidence = parse_response(resp)
            results.append(Classification(label, confidence, by="llm"))
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
