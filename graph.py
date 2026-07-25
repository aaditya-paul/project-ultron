import os
import json
import re

from colors import DIM, WHT, CYAN, GRN, YLW, RED, RST
from entities import extract_entities
from security_graph import build_security_graph, show_security_graph_summary
from rules import run_rules, show_findings

NOISE_NAMES = {"async", "function", "export", "default", "anonymous", "lambda", "handler", ""}

def _map_label_to_role(label):
    mapping = {
        "SOURCE": "other",
        "SINK_DATABASE": "database",
        "SINK_SQL": "database",
        "SINK_SHELL": "shell_exec",
        "SINK_FILE": "file_op",
        "SINK_NETWORK": "external_req",
        "AUTH": "auth",
        "VALIDATION": "validation",
        "ROUTE": "endpoint",
        "NONE": "other"
    }
    return mapping.get(label, "other")

def load_ast(workspace_dir, repo_name):
    path = os.path.join(workspace_dir, repo_name, "ast", "ast.json")
    if not os.path.isfile(path):
        print(f"  {RED}[-]{RST} AST not found at {WHT}{path}{RST}. run scan first.")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def _is_noise(fn):
    name = fn.get("name", "").strip()
    if fn.get("anonymous", False):
        return True
    if not name or len(name) < 2:
        return True
    if name.startswith("("):
        return True
    if name.lower() in NOISE_NAMES:
        return True
    return False

def resolve_import(imp, known_files):
    imp_clean = imp.strip().strip('"').strip("'")
    imp_base = imp_clean.split("/")[-1].split(".")[0]

    for f in known_files:
        f_base = os.path.splitext(f)[0]
        f_name = os.path.basename(f_base)
        if imp_base == f_name or imp_base == f_base.replace(os.sep, "/") or imp_base == f_base.replace("/", "."):
            return f

    for f in known_files:
        f_base = os.path.splitext(f)[0]
        if f_base.endswith(f"/{imp_base}") or f_base.endswith(f"\\{imp_base}"):
            return f

    return None

def find_function_def(fn_name, ast_data):
    fn_lower = fn_name.lower().replace("(", "").strip()
    for fpath, info in ast_data["files"].items():
        for fn in info["functions"]:
            if fn.get("anonymous", False):
                continue
            if fn["name"].lower() == fn_lower:
                return f"fn:{fpath}::{fn['name']}"
            if fn["name"] == fn_name:
                return f"fn:{fpath}::{fn['name']}"
    return None

def _is_backend(fpath):
    backend_indicators = (
        "/api/", "/server/", "/routes/", "/controllers/", "/middleware/",
        "route.ts", "route.js", "route.tsx",
        "server.", "api.", "db.", "schema.",
    )
    path_lower = fpath.lower()
    return any(ind in path_lower for ind in backend_indicators)

def _is_frontend(fpath):
    frontend_indicators = (
        "/components/", "/pages/", "/app/", "/views/",
        ".tsx", ".jsx",
        "component.", "page.", "layout.", "client.",
    )
    path_lower = fpath.lower()
    return any(ind in path_lower for ind in frontend_indicators)

def _classify_layer(fpath):
    if _is_backend(fpath):
        return "backend"
    if _is_frontend(fpath):
        return "frontend"
    return "shared"

def build_graph(ast_data):
    from features import extract_features
    from classifier import HybridClassifier

    # Classify all functions in the AST first to assign dependency roles
    features_list = extract_features(ast_data)
    classifier = HybridClassifier(None) # pattern-only for graph decoration
    classified = classifier.classify_all(features_list)

    fnid_to_role = {}
    for feat, res in classified:
        fnid = f"fn:{feat.file_path}::{feat.name}"
        fnid_to_role[fnid] = _map_label_to_role(res.label)

    known_files = list(ast_data["files"].keys())
    file_nodes = {}
    func_nodes = {}
    edges = []

    for fpath, info in ast_data["files"].items():
        fid = f"file:{fpath}"
        layer = _classify_layer(fpath)
        file_nodes[fid] = {
            "id": fid,
            "type": "file",
            "label": os.path.basename(fpath),
            "path": fpath,
            "language": info["language"],
            "layer": layer,
        }

        for fn in info["functions"]:
            if _is_noise(fn):
                continue
            fnid = f"fn:{fpath}::{fn['name']}"
            role = fnid_to_role.get(fnid, "other")
            func_nodes[fnid] = {
                "id": fnid,
                "type": "function",
                "label": fn["name"],
                "file": fpath,
                "params": fn["params"],
                "line": fn["line"],
                "end_line": fn.get("end_line", fn["line"]),
                "security_role": role,
                "layer": layer,
            }

    for fpath, info in ast_data["files"].items():
        fid = f"file:{fpath}"

        for imp in info["imports"]:
            resolved = resolve_import(imp, known_files)
            if resolved:
                target = f"file:{resolved}"
                edges.append({
                    "source": fid,
                    "target": target,
                    "type": "import",
                    "label": os.path.basename(resolved),
                })

    for fpath, info in ast_data["files"].items():
        for fn in info["functions"]:
            if _is_noise(fn):
                continue
            fnid = f"fn:{fpath}::{fn['name']}"

            for call in info["calls"]:
                call_text = call["text"] if isinstance(call, dict) else call
                call_line = call.get("line", 0) if isinstance(call, dict) else 0
                call_name = call_text.split("(")[0].strip().split(".")[0].split()[-1] if "(" in call_text else call_text.strip()
                if not call_name or call_name in ("if", "for", "while", "return", "import", "from", "pass", "def", "class", "const", "let", "var", "function"):
                    continue

                target = find_function_def(call_name, ast_data)
                if target and target != fnid:
                    edges.append({
                        "source": fnid,
                        "target": target,
                        "type": "call",
                        "label": call_name,
                    })

    all_nodes = {}
    all_nodes.update(file_nodes)
    all_nodes.update(func_nodes)

    roles = {}
    for n in func_nodes.values():
        r = n.get("security_role", "other")
        roles.setdefault(r, []).append(n["label"])

    layers = {"frontend": [], "backend": [], "shared": []}
    for n in func_nodes.values():
        l = n.get("layer", "shared")
        layers.setdefault(l, []).append(n["label"])

    return {
        "nodes": list(all_nodes.values()),
        "edges": edges,
        "security_roles": {r: sorted(names) for r, names in roles.items()},
        "layers": {l: sorted(names) for l, names in layers.items()},
    }

def save_graph(workspace_dir, repo_name, graph_data):
    if graph_data is None:
        return None
    gdir = os.path.join(workspace_dir, repo_name, "graph")
    os.makedirs(gdir, exist_ok=True)

    path = os.path.join(gdir, "dependency_graph.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(graph_data, f, indent=2, ensure_ascii=False)
    return path

def run_security_pipeline(ast_data, llm_client=None, verbose=False):
    entities, known_funcs = extract_entities(ast_data, llm_client)
    security_graph = build_security_graph(entities, known_funcs, ast_data)
    findings = run_rules(security_graph)

    return {
        "entities": entities,
        "security_graph": security_graph,
        "findings": findings,
    }

def render_graph(graph_data, output_path):
    try:
        import graphviz
    except ImportError:
        print(f"  {YLW}[!]{RST} graphviz not installed. install with: pip install graphviz")
        return None

    d = graphviz.Digraph(
        name="dependency_graph",
        format="svg",
        graph_attr={
            "rankdir": "LR",
            "fontsize": "10",
            "label": "Security Dependency Graph",
            "dpi": "150",
        },
        node_attr={
            "shape": "box",
            "style": "rounded,filled",
            "fontsize": "9",
        },
        edge_attr={
            "fontsize": "8",
            "arrowsize": "0.6",
        },
    )

    ROLE_COLORS = {
        "auth":         "#fce4ec",
        "database":     "#e8f5e9",
        "endpoint":     "#e3f2fd",
        "external_req": "#fff3e0",
        "file_op":      "#f3e5f5",
        "shell_exec":   "#ffebee",
        "jwt":          "#fce4ec",
        "crypto":       "#e8eaf6",
        "secrets":      "#fce4ec",
        "validation":   "#e0f2f1",
        "other":        "#f5f5f5",
    }

    def sanitize(s):
        s = s.replace("\\", "/")
        s = s.replace(":", "-")
        s = s.replace('"', "'")
        s = s.replace("\n", " ")
        s = s.replace("\r", "")
        if len(s) > 60:
            s = s[:57] + "..."
        return s

    for node in graph_data["nodes"]:
        nid = sanitize(node["id"])
        nlabel = sanitize(node["label"])
        if node["type"] == "file":
            d.node(nid, label=nlabel, fillcolor="#e1f5fe", shape="folder")
        else:
            role = node.get("security_role", "other")
            color = ROLE_COLORS.get(role, "#f5f5f5")
            d.node(nid, label=nlabel, fillcolor=color)

    for edge in graph_data["edges"]:
        src = sanitize(edge["source"])
        tgt = sanitize(edge["target"])
        elabel = sanitize(edge.get("label", ""))
        if edge["type"] == "import":
            d.edge(src, tgt, label=elabel, color="#1565c0", style="dashed")
        else:
            d.edge(src, tgt, label=elabel, color="#e65100")

    out_dir = os.path.dirname(output_path) or "."
    dot_stem = os.path.splitext(os.path.basename(output_path))[0]

    for p in [r"C:\Program Files\Graphviz\bin", r"C:\Program Files (x86)\Graphviz\bin"]:
        dot_exe = os.path.join(p, "dot.exe")
        if os.path.isfile(dot_exe):
            os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
            break

    try:
        d.render(filename=dot_stem, format="svg", directory=out_dir, quiet=True)
        svg_path = os.path.join(out_dir, dot_stem + ".svg")
        if os.path.isfile(svg_path):
            return svg_path
        return output_path
    except Exception as e:
        print(f"  {YLW}[!]{RST} graphviz render failed: {e}")
        dot_content = d.source
        dot_fallback = os.path.join(out_dir, dot_stem + ".gv")
        with open(dot_fallback, "w", encoding="utf-8") as f:
            f.write(dot_content)
        print(f"  {DIM}[*]{RST} DOT file saved -> {WHT}{dot_fallback}{RST}")
        return dot_fallback

def show_graph_summary(graph_data):
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]
    files = [n for n in nodes if n["type"] == "file"]
    funcs = [n for n in nodes if n["type"] == "function"]
    imports = [e for e in edges if e["type"] == "import"]
    calls = [e for e in edges if e["type"] == "call"]

    print(f"  {DIM}[*]{RST} dependency graph:")
    print(f"    {GRN}•{RST} {len(files)} files, {len(funcs)} functions")
    print(f"    {GRN}•{RST} {len(imports)} import edges, {len(calls)} call edges")

    roles = {}
    for n in funcs:
        r = n.get("security_role", "other")
        roles[r] = roles.get(r, 0) + 1
    if roles:
        print(f"    {DIM}[*]{RST} security roles: {', '.join(f'{GRN}{k}{RST}={v}' for k, v in sorted(roles.items()))}")

    layers = {}
    for n in funcs:
        l = n.get("layer", "shared")
        layers[l] = layers.get(l, 0) + 1
    if layers:
        print(f"    {DIM}[*]{RST} layers: {', '.join(f'{GRN}{k}{RST}={v}' for k, v in sorted(layers.items()))}")
