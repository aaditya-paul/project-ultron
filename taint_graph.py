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
            "label": "Taint Propagation Graph",
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
        if len(s) > 80:
            s = s[:77] + "..."
        return s

    added_nodes = set()
    added_edges = set()

    for idx, path in enumerate(taint_paths):
        # 1. Add Source Node
        src_id = f"src_{idx}_{sanitize(path.source.name)}"
        src_label = f"SOURCE: {path.source.name}\n{os.path.basename(path.source.file)}:L{path.source.line}"
        d.node(src_id, label=src_label, fillcolor="#ffebee", color="#c62828", fontcolor="#c62828", penwidth="2")
        added_nodes.add(src_id)

        # 2. Add Intermediate Nodes and Edges
        prev_node_id = src_id
        for e_idx, edge in enumerate(path.edges):
            to_node_id = f"var_{idx}_{e_idx}_{sanitize(edge.to_var)}"
            
            # Label for intermediate variable node
            node_label = f"{edge.to_var}\nL{edge.line}"
            
            # Determine color
            fill = "#e3f2fd"
            border = "#1565c0"
            if path.sanitized and edge.to_var in path.sanitizers:
                fill = "#e8f5e9"
                border = "#2e7d32"
                node_label += "\n[SANITIZED]"
                
            d.node(to_node_id, label=node_label, fillcolor=fill, color=border, fontcolor=border)
            
            # Edge from previous node to this one
            edge_key = (prev_node_id, to_node_id)
            if edge_key not in added_edges:
                edge_label = f"{edge.edge_type}\n({edge.expression[:30]})"
                style = "dashed" if edge.edge_type == "arg_pass" else "solid"
                d.edge(prev_node_id, to_node_id, label=edge_label, color="#757575", style=style)
                added_edges.add(edge_key)
                
            prev_node_id = to_node_id

        # 3. Add Sink Node
        sink_id = f"sink_{idx}_{sanitize(path.sink_call)}"
        sink_label = f"SINK ({path.sink_type})\n{path.sink_call}\nConf: {path.confidence}"
        d.node(sink_id, label=sink_label, fillcolor="#fff3e0", color="#ef6c00", fontcolor="#ef6c00", penwidth="2")
        
        edge_key = (prev_node_id, sink_id)
        if edge_key not in added_edges:
            d.edge(prev_node_id, sink_id, label="reaches", color="#ef6c00", penwidth="1.5")
            added_edges.add(edge_key)

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
