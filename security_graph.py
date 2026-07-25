import os
import re

from colors import DIM, WHT, GRN, YLW, RED, RST

ROUTE_FILE_PATTERNS = re.compile(r"(/api/|/routes/|route\.(ts|js|tsx)$|/pages/api/)", re.I)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

AUTH_INDICATORS = {"auth", "jwt", "token", "session", "middleware", "guard", "authenticate", "authorize"}
VALIDATION_INDICATORS = {"validate", "sanitize", "zod", "joi", "yup", "schema", "check"}


def _is_route_file(fpath: str) -> bool:
    return bool(ROUTE_FILE_PATTERNS.search(fpath))


def _extract_route_path(fpath: str) -> str:
    m = re.search(r"(?:/api/|/routes/)(.+)", fpath.replace("\\", "/"))
    if m:
        route = m.group(1)
        route = re.sub(r"/route\.(ts|js|tsx)$", "", route)
        route = re.sub(r"\.(ts|js|tsx)$", "", route)
        route = re.sub(r"\[(\w+)\]", r":\1", route)
        return "/" + route
    return "/" + os.path.splitext(os.path.basename(fpath))[0]


def _fnid_for(fpath: str, fn_name: str) -> str:
    return f"{fpath}::{fn_name}"


def build_security_graph_from_ir(ir_modules, call_graph, taint_paths):
    """Build security_graph dict from IR data.

    Produces the same format expected by rules.py and llm_detector.py:
    {"flows": [...], "subgraphs": {"auth": ..., "database": ..., "network": ...}, "summary": ...}
    """
    sources = {}
    sinks = {}
    routes = {}
    validations = {}
    auth_funcs = {}

    tag_index = {}
    for mod in ir_modules:
        for tag in mod.semantic_tags:
            tag_index.setdefault(tag.kind, []).append((tag.node_id, mod.file_path))
        for fn in mod.functions:
            fp = mod.file_path
            fnid = _fnid_for(fp, fn.name)
            if _is_route_file(fp):
                route_path = _extract_route_path(fp)
                routes[fnid] = {"label": route_path, "file": fp, "fnid": fnid}
            name_lower = fn.name.lower()
            if any(a in name_lower for a in AUTH_INDICATORS):
                auth_funcs.setdefault(fnid, []).append({"label": fn.name, "file": fp})
            if any(v in name_lower for v in VALIDATION_INDICATORS):
                validations.setdefault(fnid, []).append({"label": fn.name, "file": fp})

    src_tags = tag_index.get("HTTP_BODY", []) + tag_index.get("HTTP_PARAMS", [])
    for node_id, fpath in src_tags:
        label = f"HTTP_BODY({node_id})"
        fnid = _fnid_for(fpath, label)
        sources.setdefault(fnid, []).append({"label": label, "file": fpath, "type": "SOURCE", "fnid": fnid})

    sink_tag_map = {}
    for tag_kind in tag_index:
        if tag_kind.startswith("SINK_"):
            for node_id, fpath in tag_index[tag_kind]:
                sink_tag_map[node_id] = (tag_kind, fpath)

    for taint_path in taint_paths:
        sink_type = taint_path.sink_type or "SINK_UNKNOWN"
        sink_target = taint_path.sink_target
        file_path = taint_path.file_path

        fnid_sink = _fnid_for(file_path, sink_target)
        sinks.setdefault(fnid_sink, []).append({"label": sink_target, "file": file_path, "type": sink_type, "fnid": fnid_sink})

    call_graph_edges = {}
    if call_graph:
        for fn_id in call_graph.all_functions():
            callees = call_graph.get_callees(fn_id)
            if callees:
                call_graph_edges[fn_id] = callees

    flows = []
    for flow_id, tp in enumerate(taint_paths):
        source_fnid = _fnid_for(tp.file_path, tp.source_tag)
        sink_fnid = _fnid_for(tp.file_path, tp.sink_target)

        path_labels = [tp.source_tag] + [nid for nid in tp.path_node_ids] + [tp.sink_target]
        full_path = [source_fnid] + [f"{tp.file_path}::{nid}" for nid in tp.path_node_ids] + [sink_fnid]

        flows.append({
            "id": f"flow-{flow_id}",
            "source": tp.source_tag,
            "source_fnid": source_fnid,
            "sink": tp.sink_target,
            "sink_fnid": sink_fnid,
            "sink_type": tp.sink_type or "SINK_UNKNOWN",
            "path": full_path,
            "path_labels": path_labels,
            "validated": tp.sanitized,
            "validators": tp.sanitizer_node_ids,
            "expressions": tp.path_node_ids,
        })

    auth_graph = _build_auth_graph(routes, auth_funcs, {}, call_graph_edges)
    db_graph = _build_db_graph(flows, {})
    network_graph = _build_network_graph(sinks, {})

    by_sink_type = {}
    for f in flows:
        st = f["sink_type"]
        by_sink_type[st] = by_sink_type.get(st, 0) + 1

    unvalidated = len([f for f in flows if not f["validated"]])

    summary = {
        "total_sources": len(sources),
        "total_sinks": len(sinks),
        "total_routes": len(routes),
        "total_flows": len(flows),
        "unvalidated_flows": unvalidated,
        "flows_by_sink_type": by_sink_type,
    }

    return {
        "flows": flows,
        "subgraphs": {
            "auth": auth_graph,
            "database": db_graph,
            "network": network_graph,
        },
        "summary": summary,
    }


def _build_auth_graph(route_funcs, auth_funcs, known_funcs, call_graph):
    protected = []
    unprotected = []

    for rfnid, route in route_funcs.items():
        callees = call_graph.get(rfnid, set())
        has_auth = False
        auth_at = []
        for c in callees:
            if c in auth_funcs:
                has_auth = True
                auth_at = auth_funcs[c]
                break
        if has_auth:
            protected.append({
                "route": route["label"],
                "route_fnid": rfnid,
                "auth": [a["label"] for a in (auth_at or [])],
            })
        else:
            unprotected.append(route["label"])

    return {
        "protected": protected,
        "unprotected": unprotected,
        "total": len(route_funcs),
        "protected_count": len(protected),
        "unprotected_count": len(unprotected),
    }


def _build_db_graph(flows, known_funcs):
    db_flows = [f for f in flows if f["sink_type"] in ("SINK_DATABASE", "SINK_SQL")]
    db_ops = {}
    for f in db_flows:
        sink_label = f["sink"]
        op_type = "write" if any(k in sink_label.lower() for k in ("create", "insert", "update", "delete", "upsert", "save")) else "read"
        db_ops[f["id"]] = {
            "source": f["source"],
            "operation": sink_label[:60],
            "type": op_type,
            "validated": f["validated"],
            "path": f["path_labels"],
        }
    return {"operations": list(db_ops.values()), "total": len(db_ops)}


def _build_network_graph(sinks, known_funcs):
    net_ops = []
    for fnid, entries in sinks.items():
        for e in entries:
            if e["type"] == "SINK_NETWORK":
                net_ops.append({
                    "function": e["label"],
                    "call": e["label"],
                    "file": e["file"],
                    "line": 0,
                })
    return {"operations": net_ops, "total": len(net_ops)}


def show_security_graph_summary(sg):
    s = sg["summary"]
    print(f"  {DIM}[*]{RST} security graph:")
    print(f"    {GRN}*{RST} {s['total_sources']} sources, {s['total_sinks']} sinks, {s['total_routes']} routes")
    print(f"    {GRN}*{RST} {s['total_flows']} data-flow paths ({s['unvalidated_flows']} unvalidated)")
    if s.get("flows_by_sink_type"):
        parts = [f"{GRN}{k.replace('SINK_','').lower()}{RST}={v}" for k, v in sorted(s["flows_by_sink_type"].items())]
        print(f"    {DIM}[*]{RST} flows by sink: {', '.join(parts)}")

    auth = sg["subgraphs"]["auth"]
    if auth["unprotected"]:
        print(f"    {YLW}[!]{RST} {len(auth['unprotected'])} route(s) with no auth middleware detected")

    db = sg["subgraphs"]["database"]
    if db["operations"]:
        validated = sum(1 for op in db["operations"] if op["validated"])
        print(f"    {DIM}[*]{RST} database: {db['total']} ops ({validated} validated)")
