import os

from colors import DIM, WHT, GRN, YLW, RED, BOLD, RST

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
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "recommendation": "Add input validation (zod, joi, yup) or sanitization between source and sink",
            })
    return findings

@rule("missing-authentication", "high", "API route without authentication middleware")
def check_missing_auth(security_graph):
    findings = []
    auth = security_graph["subgraphs"]["auth"]
    for r in auth.get("unprotected", []):
        route_label = r["route"] if isinstance(r, dict) else r
        route_file = r.get("file", "") if isinstance(r, dict) else ""
        findings.append({
            "rule": "missing-authentication",
            "severity": "high",
            "title": "Route missing authentication",
            "description": f"Route {route_label} has no authentication middleware",
            "route": route_label,
            "file": route_file,
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
        fpath = op.get("file", "").replace("\\", "/").lower()
        if any(p in fpath for p in ("/frontend/", "/client/", "/src/app/", "/public/")):
            continue
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
            fpath = f.get("file", "").replace("\\", "/").lower()
            if any(p in fpath for p in ("/frontend/", "/client/", "/src/app/", "/public/")):
                continue
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

SIMPLE_EXPLANATIONS = {
    "nosql injection": (
        "An attacker could send specially-crafted data through a form or API request "
        "that tricks the database into revealing or changing information it shouldn't. "
        "This is like someone writing commands in a text field instead of actual text."
    ),
    "source_http_body": (
        "Data comes from the HTTP request body, like form fields or JSON payloads. "
        "This data is controlled by whoever sent the request."
    ),
    "source_url_param": (
        "Data comes from a URL path parameter. "
        "It could still be attacker-controlled but is sometimes validated by the framework."
    ),
    "source_session": (
        "Data comes from the user's session, which was set during login. "
        "This is generally safer because it was already authenticated."
    ),
    "source_env": (
        "Data comes from an environment variable or configuration. "
        "This is server-controlled and not influenced by user input."
    ),
    "unvalidated source-to-sink flow": (
        "User input reaches a sensitive part of the app without being checked first. "
        "This means someone could send unexpected data to database queries, file operations, "
        "or network requests."
    ),
    "missing-authentication": (
        "This page or API endpoint doesn't check if you're logged in before letting you access it. "
        "Anyone on the internet could reach it, even if it's meant to be private."
    ),
    "route missing authentication": (
        "This page or API endpoint doesn't check if you're logged in before letting you access it. "
        "Anyone on the internet could reach it, even if it's meant to be private."
    ),
    "database-write-without-validation": (
        "The app saves user data to the database without checking if it's safe first. "
        "An attacker could send harmful data that gets stored."
    ),
    "database write without validation": (
        "The app saves user data to the database without checking if it's safe first. "
        "An attacker could send harmful data that gets stored."
    ),
    "exposed-network-request": (
        "The app makes a request to an external website or service from the server. "
        "If an attacker can control where it connects, they could use it to attack other systems."
    ),
    "ssrf-dynamic-url": (
        "The app makes a network request using a URL that comes from user input. "
        "An attacker could make the server connect to internal services it shouldn't."
    ),
    "sql-injection-via-concat": (
        "The app builds database queries by combining text strings instead of using safe placeholders. "
        "An attacker could inject SQL commands through user input."
    ),
    "sql injection via string concatenation": (
        "The app builds database queries by combining text strings instead of using safe placeholders. "
        "An attacker could inject SQL commands through user input."
    ),
    "path-traversal": (
        "The app constructs file paths using user input. An attacker could read or write files "
        "outside the intended directory."
    ),
    "path traversal": (
        "The app constructs file paths using user input. An attacker could read or write files "
        "outside the intended directory."
    ),
}

SIMPLE_FIXES = {
    "nosql injection": (
        "Always clean and check user input before using it in database queries. "
        "Use parameterized queries instead of building queries by combining text strings."
    ),
    "missing-authentication": (
        "Add a login check to this route. Most web frameworks have middleware for this — "
        "a simple 'is the user logged in?' check before the page loads."
    ),
    "route missing authentication": (
        "Add a login check to this route. Most web frameworks have middleware for this — "
        "a simple 'is the user logged in?' check before the page loads."
    ),
    "database-write-without-validation": (
        "Validate all user input before saving it to the database. Use a validation library "
        "to check that data matches expected formats."
    ),
    "database write without validation": (
        "Validate all user input before saving it to the database. Use a validation library "
        "to check that data matches expected formats."
    ),
    "exposed-network-request": (
        "If the destination URL comes from user input, use an allowlist of approved domains. "
        "Prevent requests to private IP addresses (localhost, internal network)."
    ),
}


def _simple_finding(f):
    title = f.get("title", "").lower()
    severity = f.get("severity", "low").lower()
    description = f.get("description", "")
    recommendation = f.get("recommendation", "")
    route = f.get("route", "")
    source = f.get("source", "")
    sink = f.get("sink", "")
    fpath = f.get("file", "")
    rule = f.get("rule", "")

    explanation = ""
    for key, text in SIMPLE_EXPLANATIONS.items():
        if key in title or key in rule:
            explanation = text
            break
    if not explanation and severity == "high":
        explanation = description.split(".")[0] + "." if description else ""
    if not explanation:
        explanation = description.split(".")[0] + "." if description else ""

    fix = ""
    for key, text in SIMPLE_FIXES.items():
        if key in title or key in rule:
            fix = text
            break
    if not fix and recommendation:
        fix = recommendation

    where_parts = []
    if route:
        where_parts.append(route)
    if fpath:
        where_parts.append(fpath)
    if source and sink:
        where_parts.append(f"{source} -> {sink}")
    if not where_parts and source:
        where_parts.append(source)
    if not where_parts and sink:
        where_parts.append(sink)

    return {
        "title": f.get("title", "Issue"),
        "severity": severity,
        "explanation": explanation,
        "fix": fix,
        "where": where_parts,
        "route": route,
        "source": source,
        "sink": sink,
        "rule": rule,
    }


def show_findings_summary(findings, security_graph, node_index, auth_validated_routes=None):
    """Show a simple, non-technical summary of findings."""
    if not findings:
        print(f"\n  {GRN}[+]{RST} no security issues found")
        return

    llm_findings = [f for f in findings if f.get("flow_id", "").startswith("flow-")]
    rule_findings = [f for f in findings if not f.get("flow_id", "").startswith("flow-")]

    confirmed = [_simple_finding(f) for f in llm_findings]
    others = [_simple_finding(f) for f in rule_findings]

    if auth_validated_routes is not None:
        others = [f for f in others if f["route"] in auth_validated_routes or not f["route"]]

    has_real = confirmed or any(f.get("severity") != "low" for f in others)

    print()
    print(f"  {WHT}{BOLD}═══════════════════════════════════════════════════{RST}")
    print(f"  {WHT}{BOLD}  SECURITY REPORT{RST}")
    print(f"  {WHT}{BOLD}═══════════════════════════════════════════════════{RST}")

    if confirmed:
        label = "y" if len(confirmed) == 1 else "ies"
        print(f"\n  {RED}● {len(confirmed)} Confirmed Vulnerabilit{label}{RST}")
        print(f"  {DIM}These are real problems that need attention:{RST}\n")
        for f in confirmed:
            sev = f["severity"]
            icon = RED + "[!]" if sev == "high" else YLW + "[!]" if sev == "medium" else DIM + "[i]"
            sev_label = {"high": "HIGH", "medium": "MED", "low": "LOW"}.get(sev, "INFO")
            print(f"  {icon}{RST} {WHT}{BOLD}{f['title']}{RST} ({sev_label})")
            print(f"     {f['explanation']}")
            if f["where"]:
                print(f"     {DIM}where:{RST} {', '.join(f['where'][:2])}")
            if f["fix"]:
                print(f"     {DIM}fix:{RST} {f['fix']}")
            print()

    if others:
        by_type = {}
        for f in others:
            k = f["rule"]
            by_type.setdefault(k, {"title": f["title"], "severity": f["severity"], "items": []})
            by_type[k]["items"].append(f)

        for k, g in by_type.items():
            sev = g["severity"]
            icon = (RED + "[!]") if sev == "high" else (YLW + "[!]") if sev == "medium" else DIM + "[i]"
            count = len(g["items"])
            label = {"high": "attention needed", "medium": "check recommended", "low": "info"}.get(sev, "info")
            print(f"  {icon}{RST} {count} {g['title']} ({label})")
            explanation = g["items"][0].get("explanation", "")
            if explanation:
                print(f"     {explanation}")
            where_list = []
            for item in g["items"]:
                for w in item["where"]:
                    if w not in where_list:
                        where_list.append(w)
            if where_list:
                print(f"     {DIM}routes:{RST} {', '.join(where_list[:6])}")
                if len(where_list) > 6:
                    print(f"     {DIM}       ... and {len(where_list) - 6} more{RST}")
            fix = g["items"][0].get("fix", "")
            if fix:
                print(f"     {DIM}fix:{RST} {fix}")
            print()

    if not has_real:
        print(f"\n  {GRN}● No real security issues found{RST}")
        print(f"  {DIM}Minor warnings above are either low-risk or not exploitable.{RST}\n")

    print(f"  {WHT}{BOLD}═══════════════════════════════════════════════════{RST}")
    print()

    if auth_validated_routes is not None:
        total_auth = len([f for f in rule_findings if f.get("rule") == "missing-authentication"])
        remaining_auth = len([f for f in others if f.get("rule") == "missing-authentication"])
        if remaining_auth < total_auth:
            print(f"  {DIM}[*] AI checked {total_auth} routes for missing login checks, "
                  f"flagged {remaining_auth} as likely needing authentication.{RST}\n")


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
