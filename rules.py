import os

from colors import DIM, WHT, GRN, YLW, RED, RST

RULE_REGISTRY = []

def rule(name, severity, description):
    def decorator(func):
        RULE_REGISTRY.append({
            "name": name,
            "severity": severity,
            "description": description,
            "check": func,
        })
        return func
    return decorator

def is_concatenated(expr):
    if not expr:
        return False
    expr_lower = expr.lower()
    return any(kw in expr_lower for kw in ("+", ".concat", "format", "f\"", "f'", "%s", "${"))

def is_path_manipulation(expr):
    if not expr:
        return False
    expr_lower = expr.lower()
    return any(kw in expr_lower for kw in ("+", "join", "resolve", "/", "\\", "path", "file"))

@rule("unvalidated-source-to-sink", "high", "Untrusted input reaches a sensitive operation without validation")
def check_unvalidated_flows(security_graph):
    findings = []
    for f in security_graph["flows"]:
        if not f["validated"]:
            findings.append({
                "rule": "unvalidated-source-to-sink",
                "severity": "high",
                "title": "Unvalidated source-to-sink flow",
                "description": f"Data flows from {f['source']} to {f['sink']} without validation",
                "flow_id": f["id"],
                "source": f["source"],
                "sink": f["sink"],
                "path": f["path_labels"],
                "recommendation": "Add input validation (zod, joi, yup) or sanitization between source and sink",
            })
    return findings

@rule("missing-authentication", "high", "API route without authentication middleware")
def check_missing_auth(security_graph):
    findings = []
    auth = security_graph["subgraphs"]["auth"]
    for route in auth.get("unprotected", []):
        findings.append({
            "rule": "missing-authentication",
            "severity": "high",
            "title": "Route missing authentication",
            "description": f"Route {route} has no authentication middleware",
            "route": route,
            "recommendation": "Add authentication middleware (JWT verification, session check) to this route",
        })
    return findings

@rule("database-write-without-validation", "medium", "Database write operation without input validation")
def check_db_write_validation(security_graph):
    findings = []
    db = security_graph["subgraphs"]["database"]
    for op in db.get("operations", []):
        if op["type"] == "write" and not op["validated"]:
            findings.append({
                "rule": "database-write-without-validation",
                "severity": "medium",
                "title": "Database write without validation",
                "description": f"Database write '{op['operation']}' has no input validation in its data-flow path",
                "source": op.get("source", "?"),
                "operation": op["operation"],
                "recommendation": "Validate input before database write to prevent injection attacks",
            })
    return findings

@rule("exposed-network-request", "medium", "Server-side network request to external destination")
def check_network_requests(security_graph):
    findings = []
    net = security_graph["subgraphs"]["network"]
    for op in net.get("operations", []):
        findings.append({
            "rule": "exposed-network-request",
            "severity": "medium",
            "title": "Server-side network request",
            "description": f"Function {op['function']} makes external request: {op['call']}",
            "function": op["function"],
            "call": op["call"],
            "file": op["file"],
            "line": op["line"],
            "recommendation": "Verify the destination URL is not attacker-controlled to prevent SSRF",
        })
    return findings

@rule("sql-injection-via-concat", "high", "SQL injection vulnerability due to string concatenation or formatting in query construction")
def check_sql_injection(security_graph):
    findings = []
    for f in security_graph["flows"]:
        if f["sink_type"] in ("SINK_SQL", "SINK_DATABASE") and not f["validated"]:
            all_exprs = f.get("expressions", []) + [f["sink"]]
            if any(is_concatenated(expr) for expr in all_exprs):
                findings.append({
                    "rule": "sql-injection-via-concat",
                    "severity": "high",
                    "title": "SQL injection via string concatenation",
                    "description": f"Untrusted input reaches SQL sink '{f['sink']}' via string concatenation/formatting",
                    "source": f["source"],
                    "sink": f["sink"],
                    "path": f["path_labels"],
                    "recommendation": "Use parameterized queries / prepared statements instead of string concatenation.",
                })
    return findings

@rule("path-traversal", "high", "Path traversal vulnerability due to unsanitized user input in file paths")
def check_path_traversal(security_graph):
    findings = []
    for f in security_graph["flows"]:
        if f["sink_type"] == "SINK_FILE" and not f["validated"]:
            all_exprs = f.get("expressions", []) + [f["sink"]]
            if any(is_path_manipulation(expr) for expr in all_exprs):
                findings.append({
                    "rule": "path-traversal",
                    "severity": "high",
                    "title": "Path traversal vulnerability",
                    "description": f"Untrusted input reaches file operation '{f['sink']}' via path construction/concatenation",
                    "source": f["source"],
                    "sink": f["sink"],
                    "path": f["path_labels"],
                    "recommendation": "Sanitize input paths, resolve paths using standard library secure methods, and verify paths are within a allowed directory boundary.",
                })
    return findings

@rule("ssrf-dynamic-url", "medium", "Server-Side Request Forgery (SSRF) due to dynamic URL from untrusted source")
def check_ssrf(security_graph):
    findings = []
    for f in security_graph["flows"]:
        if f["sink_type"] == "SINK_NETWORK" and not f["validated"]:
            findings.append({
                "rule": "ssrf-dynamic-url",
                "severity": "medium",
                "title": "Potential SSRF",
                "description": f"Untrusted input flows into network request sink '{f['sink']}'",
                "source": f["source"],
                "sink": f["sink"],
                "path": f["path_labels"],
                "recommendation": "Use an allowlist of approved URLs/domains and prevent requests to private IP ranges (localhost, loopback, internal network).",
            })
    return findings

def run_rules(security_graph):
    all_findings = []
    for r in RULE_REGISTRY:
        try:
            findings = r["check"](security_graph)
            for f in findings:
                f["rule_name"] = r["name"]
                f["severity"] = r["severity"]
            all_findings.extend(findings)
        except Exception as e:
            print(f"  {YLW}[!]{RST} rule '{r['name']}' failed: {e}")
    return all_findings

def show_findings(findings):
    if not findings:
        print(f"  {GRN}[+]{RST} no security findings")
        return

    by_severity = {"high": [], "medium": [], "low": []}
    for f in findings:
        by_severity.setdefault(f.get("severity", "low"), []).append(f)

    print(f"  {YLW}[!]{RST} {len(findings)} security finding(s):")
    for severity in ("high", "medium", "low"):
        for f in by_severity.get(severity, []):
            icon = {"high": RED, "medium": YLW, "low": DIM}.get(severity, DIM)
            label = {"high": "HIGH", "medium": "MED", "low": "LOW"}.get(severity, "INFO")
            print(f"    {icon}[{label}]{RST} {f['title']}")
            print(f"           {DIM}{f.get('description', '')}{RST}")
