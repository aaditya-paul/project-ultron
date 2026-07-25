import os
import re
from features import extract_features
from classifier import HybridClassifier

ENTITY_TYPES = {
    "ROUTE": "API Route / Endpoint",
    "SOURCE": "Attacker-Controlled Input",
    "SINK_DATABASE": "Database Operation",
    "SINK_SHELL": "Shell Command Execution",
    "SINK_FILE": "File Operation",
    "SINK_NETWORK": "External Network Request",
    "SINK_SQL": "Raw SQL Execution",
    "AUTH_MIDDLEWARE": "Authentication Middleware",
    "AUTH_CHECK": "Authorization / Permission Check",
    "JWT_SIGN": "JWT Signing",
    "JWT_VERIFY": "JWT Verification",
    "VALIDATION": "Input Validation / Sanitization",
    "SECRETS_ACCESS": "Secrets / Environment Access",
    "COOKIE_ACCESS": "Cookie Access",
}

ROUTE_FILE_PATTERNS = [
    r"(^|[/\\])api[/\\].*[/\\]route\.\w+$",
    r"(^|[/\\])api[/\\].*\.route\.\w+$",
    r"(^|[/\\])routes[/\\]",
    r"(^|[/\\])controllers[/\\]",
    r"(^|[/\\])handlers[/\\]",
    r"(^|[/\\])pages[/\\]api[/\\]",
]

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

def _is_route_file(fpath):
    for pat in ROUTE_FILE_PATTERNS:
        if re.search(pat, fpath, re.IGNORECASE):
            return True
    return False

def _extract_route_path(fpath):
    parts = fpath.replace("\\", "/").split("/")
    try:
        api_idx = next(i for i, p in enumerate(parts) if p == "api")
        route_parts = parts[api_idx + 1:]
        if route_parts and route_parts[-1].startswith("route."):
            route_parts = route_parts[:-1]
        route_path = "/" + "/".join(route_parts)
        return route_path
    except StopIteration:
        return None

def extract_entities(ast_data, llm_client=None):
    entities = []
    known_func_ids = {}

    # 1. Extract structural features from AST
    features_list = extract_features(ast_data)

    # 2. Run hybrid two-pass classification
    classifier = HybridClassifier(llm_client)
    classified_features = classifier.classify_all(features_list)

    # Save stats in class for later retrieval if needed
    extract_entities.stats = classifier.stats

    # 3. Translate classification outputs to entities & known_func_ids
    for feat, res in classified_features:
        fn_name = feat.name
        fpath = feat.file_path
        fnid = f"{fpath}::{fn_name}"

        # Initialize function metadata in known_func_ids
        known_func_ids[fnid] = {
            "name": fn_name,
            "file": fpath,
            "line": feat.line,
            "params": feat.params,
            "calls": [{"text": c, "line": feat.line} for c in feat.calls_made],
            "is_source": False,
            "source_labels": [],
            "sinks": [],
            "validations": [],
            "sec_patterns": [],
            "classification": res.to_dict()
        }

        # Check route conditions: either classified as ROUTE, or is in route file and has HTTP method name
        is_route_file = _is_route_file(fpath)
        is_http_method = fn_name.upper() in HTTP_METHODS
        
        if res.label == "ROUTE" or (is_route_file and is_http_method):
            route_path = _extract_route_path(fpath)
            method = fn_name.upper() if is_http_method else "ANY"
            route_label = f"{method} {route_path}" if route_path else fn_name.upper()
            entities.append({
                "type": "ROUTE",
                "label": route_label,
                "file": fpath,
                "line": feat.line,
                "fnid": fnid,
                "metadata": {
                    "method": method,
                    "path": route_path or fpath,
                    "confidence": res.confidence,
                    "by": res.by
                },
            })

        if res.label == "SOURCE":
            known_func_ids[fnid]["is_source"] = True
            source_lbl = f"param:{feat.params[0]}" if feat.params else fn_name
            known_func_ids[fnid]["source_labels"].append(source_lbl)
            entities.append({
                "type": "SOURCE",
                "label": source_lbl,
                "file": fpath,
                "line": feat.line,
                "fnid": fnid,
                "metadata": {
                    "param_detail": source_lbl,
                    "confidence": res.confidence,
                    "by": res.by
                },
            })

        elif res.label in ("SINK_DATABASE", "SINK_SQL"):
            # Map both SINK_DATABASE and SINK_SQL to SINK_DATABASE or SINK_SQL based on label
            stype = "SINK_DATABASE" if res.label == "SINK_DATABASE" else "SINK_SQL"
            known_func_ids[fnid]["sinks"].append({"type": stype, "label": fn_name})
            entities.append({
                "type": stype,
                "label": fn_name,
                "file": fpath,
                "line": feat.line,
                "fnid": fnid,
                "metadata": {
                    "call": fn_name,
                    "confidence": res.confidence,
                    "by": res.by
                },
            })

        elif res.label == "SINK_SHELL":
            known_func_ids[fnid]["sinks"].append({"type": "SINK_SHELL", "label": fn_name})
            entities.append({
                "type": "SINK_SHELL",
                "label": fn_name,
                "file": fpath,
                "line": feat.line,
                "fnid": fnid,
                "metadata": {
                    "call": fn_name,
                    "confidence": res.confidence,
                    "by": res.by
                },
            })

        elif res.label == "SINK_FILE":
            known_func_ids[fnid]["sinks"].append({"type": "SINK_FILE", "label": fn_name})
            entities.append({
                "type": "SINK_FILE",
                "label": fn_name,
                "file": fpath,
                "line": feat.line,
                "fnid": fnid,
                "metadata": {
                    "call": fn_name,
                    "confidence": res.confidence,
                    "by": res.by
                },
            })

        elif res.label == "SINK_NETWORK":
            known_func_ids[fnid]["sinks"].append({"type": "SINK_NETWORK", "label": fn_name})
            entities.append({
                "type": "SINK_NETWORK",
                "label": fn_name,
                "file": fpath,
                "line": feat.line,
                "fnid": fnid,
                "metadata": {
                    "call": fn_name,
                    "confidence": res.confidence,
                    "by": res.by
                },
            })

        elif res.label == "AUTH":
            known_func_ids[fnid]["sec_patterns"].append({"type": "AUTH_CHECK", "label": fn_name})
            entities.append({
                "type": "AUTH_CHECK",
                "label": fn_name,
                "file": fpath,
                "line": feat.line,
                "fnid": fnid,
                "metadata": {
                    "confidence": res.confidence,
                    "by": res.by
                },
            })

        elif res.label == "VALIDATION":
            known_func_ids[fnid]["validations"].append(fn_name)
            entities.append({
                "type": "VALIDATION",
                "label": fn_name,
                "file": fpath,
                "line": feat.line,
                "fnid": fnid,
                "metadata": {
                    "pattern": fn_name,
                    "confidence": res.confidence,
                    "by": res.by
                },
            })

    return entities, known_func_ids
