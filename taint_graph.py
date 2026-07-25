import os

def render_taint_graph(taint_paths, output_path):
    try:
        import graphviz
    except ImportError:
        print("  [!] graphviz not installed. install with: pip install graphviz")
        return None

    d = graphviz.Digraph(
        name="taint_graph",
        format="svg",
        graph_attr={
            "rankdir": "LR",
            "fontsize": "10",
            "label": "IR Taint Propagation Graph",
            "dpi": "150",
            "bgcolor": "#fafafa",
        },
        node_attr={
            "shape": "box",
            "style": "rounded,filled",
            "fontsize": "9",
            "fontname": "Arial",
        },
        edge_attr={
            "fontsize": "8",
            "arrowsize": "0.6",
            "fontname": "Arial",
        },
    )

    def sanitize(s):
        s = s.replace("\\", "/")
        s = s.replace(":", "-")
        s = s.replace('"', "'")
        s = s.replace("\n", " ")
        s = s.replace("\r", "")
        if len(s) > 60:
            s = s[:57] + "..."
        return s

    def node_type_label(nid):
        if nid.startswith("ACCESS_"):
            return "access"
        elif nid.startswith("ASSIGN_"):
            return "assign"
        elif nid.startswith("VAR_"):
            return "var"
        elif nid.startswith("CALL_"):
            return "call"
        elif nid.startswith("CALLE_"):
            return "expr"
        elif nid.startswith("RET_"):
            return "return"
        elif nid.startswith("BRANCH_"):
            return "branch"
        elif nid.startswith("LIT_"):
            return "literal"
        return "node"

    added_nodes = set()
    added_edges = set()

    for idx, path in enumerate(taint_paths):
        file_label = os.path.basename(path.file_path) if path.file_path else "?"

        src_id = f"src_{idx}_{sanitize(path.source_node_id)}"
        src_label = f"SOURCE: {path.source_tag}\n{path.source_node_id}\n[{file_label}]"
        d.node(src_id, label=src_label, fillcolor="#ffebee", color="#c62828", fontcolor="#c62828", penwidth="2")
        added_nodes.add(src_id)

        prev_id = src_id
        intermediates = path.path_node_ids[1:] if len(path.path_node_ids) > 1 else []

        for i, nid in enumerate(intermediates):
            nid_safe = sanitize(nid)
            node_id = f"mid_{idx}_{i}_{nid_safe}"
            nt = node_type_label(nid)
            short_id = nid[:20] + "..." if len(nid) > 23 else nid

            fill = "#e3f2fd"
            border = "#1565c0"
            label_extra = ""
            if nid in path.sanitizer_node_ids:
                fill = "#e8f5e9"
                border = "#2e7d32"
                label_extra = "\n[SANITIZED]"
            elif path.sanitized and nid in path.path_node_ids:
                pass

            d.node(node_id, label=f"{nt}: {short_id}{label_extra}", fillcolor=fill, color=border, fontcolor=border)
            added_nodes.add(node_id)

            ek = (prev_id, node_id)
            if ek not in added_edges:
                prefix = nid.split("_")[0] if "_" in nid else ""
                edge_label = f"{prefix}"
                d.edge(prev_id, node_id, label=edge_label, color="#757575")
                added_edges.add(ek)
            prev_id = node_id

        sink_id = f"sink_{idx}_{sanitize(path.sink_node_id)}"
        sink_label = f"SINK: {path.sink_target}\n({path.sink_type})\n{path.sink_node_id}\nConf: {path.confidence}\n[{file_label}]"
        fill_sink = "#fff3e0"
        border_sink = "#ef6c00"
        if path.sanitized:
            fill_sink = "#e8f5e9"
            border_sink = "#2e7d32"
        d.node(sink_id, label=sink_label, fillcolor=fill_sink, color=border_sink, fontcolor=border_sink, penwidth="2")
        added_nodes.add(sink_id)

        ek = (prev_id, sink_id)
        if ek not in added_edges:
            d.edge(prev_id, sink_id, label="reaches", color="#ef6c00", penwidth="1.5")
            added_edges.add(ek)

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
        print(f"  [!] graphviz taint render failed: {e}")
        dot_content = d.source
        dot_fallback = os.path.join(out_dir, dot_stem + ".gv")
        with open(dot_fallback, "w", encoding="utf-8") as f:
            f.write(dot_content)
        return dot_fallback
