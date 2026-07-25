import os
import json
import re

from colors import DIM, WHT, CYAN, GRN, YLW, RED, RST

def load_ast(workspace_dir, repo_name):
    path = os.path.join(workspace_dir, repo_name, "ast", "ast.json")
    if not os.path.isfile(path):
        print(f"  {RED}[-]{RST} AST not found at {WHT}{path}{RST}. run scan first.")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)

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
            if fn["name"].lower() == fn_lower:
                return f"{fpath}::{fn['name']}"
            if fn["name"] == fn_name:
                return f"{fpath}::{fn['name']}"
    return None

def build_graph(ast_data):
    known_files = list(ast_data["files"].keys())
    file_nodes = {}
    func_nodes = {}
    edges = []

    for fpath, info in ast_data["files"].items():
        fid = f"file:{fpath}"
        file_nodes[fid] = {
            "id": fid,
            "type": "file",
            "label": os.path.basename(fpath),
            "path": fpath,
            "language": info["language"],
        }

        for fn in info["functions"]:
            fnid = f"fn:{fpath}::{fn['name']}"
            func_nodes[fnid] = {
                "id": fnid,
                "type": "function",
                "label": fn["name"],
                "file": fpath,
                "params": fn["params"],
                "line": fn["line"],
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
            fnid = f"fn:{fpath}::{fn['name']}"
            fn_lines = set(range(fn["line"], fn["end_line"] + 1))

            for call in info["calls"]:
                call_name = call.split("(")[0].strip().split(".")[0].split()[-1] if "(" in call else call.strip()
                if not call_name or call_name in ("if", "for", "while", "return", "import", "from", "pass", "def", "class", "const", "let", "var", "function"):
                    continue

                target = find_function_def(call_name, ast_data)
                if target:
                    edges.append({
                        "source": fnid,
                        "target": target,
                        "type": "call",
                        "label": call_name,
                    })

    all_nodes = {}
    all_nodes.update(file_nodes)
    all_nodes.update(func_nodes)

    return {
        "nodes": list(all_nodes.values()),
        "edges": edges,
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
            "label": "Dependency Graph",
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

    for node in graph_data["nodes"]:
        if node["type"] == "file":
            d.node(node["id"], label=node["label"], fillcolor="#e1f5fe")
        else:
            d.node(node["id"], label=node["label"], fillcolor="#fff9c4")

    for edge in graph_data["edges"]:
        if edge["type"] == "import":
            d.edge(edge["source"], edge["target"], label=edge.get("label", ""), color="#1565c0", style="dashed")
        else:
            d.edge(edge["source"], edge["target"], label=edge.get("label", ""), color="#e65100")

    dot_path = output_path.replace(".svg", ".gv")
    try:
        d.render(filename=dot_path, format="svg", directory=os.path.dirname(output_path) or ".", quiet=True)
        return output_path
    except Exception as e:
        dot_content = d.source
        dot_fallback = output_path.replace(".svg", ".gv")
        with open(dot_fallback, "w", encoding="utf-8") as f:
            f.write(dot_content)
        print(f"  {YLW}[!]{RST} graphviz system binaries not found. DOT file saved instead.")
        print(f"  {DIM}[*]{RST} install Graphviz from https://graphviz.org/download/")
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
