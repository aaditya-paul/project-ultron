import os
import json

from colors import DIM, WHT, CYAN, GRN, YLW, RED, RST


NOISE_NAMES = {"async", "function", "export", "default", "anonymous", "lambda", "handler", ""}

TAG_ROLE_MAP = {
    "HTTP_BODY": "source",
    "HTTP_PARAMS": "source",
    "SOURCE_HTTP_BODY": "source",
    "SOURCE_URL_PARAM": "source",
    "SOURCE_URL_QUERY": "source",
    "SOURCE_SESSION": "source",
    "SOURCE_ENV": "source",
    "FILE_READ": "source",
    "ENV_VAR": "source",
    "COOKIE": "source",
    "AUTH_HEADER": "source",
    "SINK_DATABASE": "database",
    "SINK_SQL": "database",
    "SINK_SHELL": "shell_exec",
    "SINK_EXEC": "shell_exec",
    "SINK_FILE": "file_op",
    "SINK_NETWORK": "external_req",
    "VALIDATION": "validation",
    "VALIDATION_GATE": "validation",
    "AUTH": "auth",
    "ROUTE": "endpoint",
}


def load_ast(workspace_dir, repo_name):
    path = os.path.join(workspace_dir, repo_name, "ast", "ast.json")
    if not os.path.isfile(path):
        print(f"  {RED}[-]{RST} AST not found at {WHT}{path}{RST}. run scan first.")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _is_noise(fn_name):
    name = fn_name.strip()
    if not name or len(name) < 2:
        return True
    if name.startswith("("):
        return True
    if name.lower() in NOISE_NAMES:
        return True
    return False


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


def _fnid_for(fpath, fn_name):
    return f"fn:{fpath}::{fn_name}"


def _tag_to_role(tag_kind):
    for prefix, role in TAG_ROLE_MAP.items():
        if tag_kind == prefix or tag_kind.startswith(prefix):
            return role
    return "other"


def build_ir_dependency_graph(ir_modules, call_graph):
    """Build a dependency graph dict from IR modules and call graph."""
    file_nodes = {}
    func_nodes = {}
    edges = []

    role_map = {}
    for mod in ir_modules:
        for tag in mod.semantic_tags:
            role_map[tag.node_id] = _tag_to_role(tag.kind)

    fn_id_to_name = {}
    for mod in ir_modules:
        for fn in mod.functions:
            fn_id_to_name[fn.id] = fn.name

    for mod in ir_modules:
        fpath = mod.file_path
        fid = f"file:{fpath}"
        layer = _classify_layer(fpath)
        file_nodes[fid] = {
            "id": fid,
            "type": "file",
            "label": os.path.basename(fpath),
            "path": fpath,
            "language": mod.language,
            "layer": layer,
        }

        for fn in mod.functions:
            if _is_noise(fn.name):
                continue
            fnid = _fnid_for(fpath, fn.name)
            role = role_map.get(fn.id, "other")
            func_nodes[fnid] = {
                "id": fnid,
                "type": "function",
                "label": fn.name,
                "file": fpath,
                "params": fn.params,
                "line": fn.line,
                "security_role": role,
                "layer": layer,
            }

    if call_graph:
        for caller_id in call_graph.all_functions():
            caller_name = fn_id_to_name.get(caller_id, caller_id)
            for callee_id in call_graph.get_callees(caller_id):
                callee_name = fn_id_to_name.get(callee_id, callee_id)
                caller_fnid = _fnid_for(call_graph.fn_file(caller_id), caller_name)
                callee_fnid = _fnid_for(call_graph.fn_file(callee_id), callee_name)
                if caller_fnid in func_nodes and callee_fnid in func_nodes:
                    edges.append({
                        "source": caller_fnid,
                        "target": callee_fnid,
                        "type": "call",
                        "label": callee_name,
                    })

    for mod in ir_modules:
        fpath = mod.file_path
        fid = f"file:{fpath}"
        for fn in mod.functions:
            fnid = _fnid_for(fpath, fn.name)
            if fnid in func_nodes:
                edges.append({
                    "source": fid,
                    "target": fnid,
                    "type": "contains",
                    "label": fn.name,
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
        "source":       "#ffebee",
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
        if edge["type"] == "import" or edge["type"] == "contains":
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
    calls = [e for e in edges if e["type"] == "call"]

    print(f"  {DIM}[*]{RST} dependency graph:")
    print(f"    {GRN}*{RST} {len(files)} files, {len(funcs)} functions")
    print(f"    {GRN}*{RST} {len(calls)} call edges")

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


def render_security_graph(security_graph, output_path):
    try:
        import graphviz
    except ImportError:
        print(f"  {YLW}[!]{RST} graphviz not installed. install with: pip install graphviz")
        return None

    d = graphviz.Digraph(
        name="security_graph",
        format="svg",
        graph_attr={
            "rankdir": "TB",
            "fontsize": "10",
            "label": "Security Analysis Graph",
            "dpi": "150",
            "bgcolor": "#fafafa",
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

    def sanitize(s):
        s = s.replace("\\", "/")
        s = s.replace(":", "-")
        s = s.replace('"', "'")
        s = s.replace("\n", " ")
        s = s.replace("\r", "")
        if len(s) > 50:
            s = s[:47] + "..."
        return s

    flows = security_graph.get("flows", [])
    subgraphs = security_graph.get("subgraphs", {})
    summary = security_graph.get("summary", {})

    # Summary cluster
    with d.subgraph(name="cluster_summary") as s:
        s.attr(label="Summary", style="filled", fillcolor="#f5f5f5", color="#9e9e9e")
        s.node("summary_info", label=(
            f"Sources: {summary.get('total_sources', 0)} | "
            f"Sinks: {summary.get('total_sinks', 0)} | "
            f"Routes: {summary.get('total_routes', 0)} | "
            f"Flows: {summary.get('total_flows', 0)} | "
            f"Unvalidated: {summary.get('unvalidated_flows', 0)}"
        ), shape="note", fillcolor="#e8eaf6", color="#3949ab")

    # Auth subgraph cluster
    auth = subgraphs.get("auth", {})
    if auth.get("protected") or auth.get("unprotected"):
        with d.subgraph(name="cluster_auth") as s:
            s.attr(label="Auth", style="filled", fillcolor="#fce4ec", color="#c62828")
            for p in auth.get("protected", []):
                pid = sanitize(f"auth_protected_{p['route']}")
                s.node(pid, label=f"PROTECTED: {p['route']}", fillcolor="#c8e6c9", color="#2e7d32")
            for r in auth.get("unprotected", []):
                rid = sanitize(f"auth_unprotected_{r}")
                s.node(rid, label=f"UNPROTECTED: {r}", fillcolor="#ffcdd2", color="#c62828")

    # Database subgraph cluster
    db = subgraphs.get("database", {})
    db_ops = db.get("operations", [])
    if db_ops:
        with d.subgraph(name="cluster_database") as s:
            s.attr(label=f"Database ({db.get('total', 0)} ops)", style="filled", fillcolor="#e8f5e9", color="#2e7d32")
            for op in db_ops:
                oid = sanitize(f"db_{op['source']}_{op['operation']}")
                validated = op.get("validated", False)
                label = f"{'[V]' if validated else '[U]'} {op['source']} -> {op['operation']}"
                fill = "#c8e6c9" if validated else "#ffcc80"
                s.node(oid, label=label, fillcolor=fill)

    # Network subgraph cluster
    net = subgraphs.get("network", {})
    net_ops = net.get("operations", [])
    if net_ops:
        with d.subgraph(name="cluster_network") as s:
            s.attr(label=f"Network ({net.get('total', 0)} ops)", style="filled", fillcolor="#fff3e0", color="#e65100")
            for op in net_ops:
                nid = sanitize(f"net_{op.get('function', '?')}")
                s.node(nid, label=f"{op.get('function', '?')} ({op.get('file', '?')})", fillcolor="#ffe0b2")

    # Flow paths
    for flow in flows:
        flow_id = flow.get("id", "flow")
        source_label = flow.get("source", "?")
        sink_label = flow.get("sink", "?")
        sink_type = flow.get("sink_type", "?")
        path_labels = flow.get("path_labels", [])

        with d.subgraph(name=f"cluster_{sanitize(flow_id)}") as s:
            s.attr(
                label=f"{flow_id}: {source_label} -> {sink_label} ({sink_type})",
                style="filled",
                fillcolor="#f3e5f5",
                color="#7b1fa2",
                fontcolor="#4a148c"
            )

            # Source node
            src_id = sanitize(f"{flow_id}_source")
            s.node(src_id, label=f"SOURCE: {source_label}", fillcolor="#ffebee", color="#c62828", fontcolor="#c62828", penwidth="2")

            prev = src_id
            for step_label in path_labels[1:-1]:
                step_id = sanitize(f"{flow_id}_{step_label}")
                s.node(step_id, label=step_label, fillcolor="#e3f2fd", color="#1565c0")
                s.edge(prev, step_id, color="#757575")
                prev = step_id

            # Sink node
            validated = flow.get("validated", False)
            sink_id = sanitize(f"{flow_id}_sink")
            fill = "#c8e6c9" if validated else "#fff3e0"
            border = "#2e7d32" if validated else "#ef6c00"
            label = f"SINK: {sink_label}\n({sink_type})"
            if validated:
                label += "\n[SANITIZED]"
            s.node(sink_id, label=label, fillcolor=fill, color=border, fontcolor=border, penwidth="2")
            s.edge(prev, sink_id, color="#ef6c00", penwidth="1.5")

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
        print(f"  {YLW}[!]{RST} graphviz security graph render failed: {e}")
        dot_content = d.source
        dot_fallback = os.path.join(out_dir, dot_stem + ".gv")
        with open(dot_fallback, "w", encoding="utf-8") as f:
            f.write(dot_content)
        print(f"  {DIM}[*]{RST} DOT file saved -> {WHT}{dot_fallback}{RST}")
        return dot_fallback
