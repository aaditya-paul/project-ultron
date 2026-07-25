import os
import re

from colors import DIM, WHT, GRN, YLW, RED, RST

def _call_text(c):
    return c["text"] if isinstance(c, dict) else c

def _call_line(c):
    return c.get("line", 0) if isinstance(c, dict) else 0

def _resolve_call_target(call_text, known_funcs):
    call_name = call_text.split("(")[0].strip().split(".")[0].split()[-1] if "(" in call_text else call_text.strip()
    if not call_name or call_name in ("if", "for", "while", "return", "import", "from", "pass", "def", "class", "const", "let", "var", "function", "new", "try", "catch", "throw", "await", "yield"):
        return None

    call_lower = call_name.lower().replace("(", "").strip()
    for fnid, info in known_funcs.items():
        if info["name"].lower() == call_lower:
            return fnid
    return None

def _get_callees(fn_calls, known_funcs):
    callees = set()
    for c in fn_calls:
        target = _resolve_call_target(_call_text(c), known_funcs)
        if target:
            callees.add(target)
    return callees

def build_security_graph(entities, known_funcs, ast_data=None):
    source_funcs = {}
    sink_funcs = {}
    route_funcs = {}
    validation_funcs = {}
    auth_funcs = {}

    for e in entities:
        fnid = e.get("fnid", "")
        if e["type"] == "SOURCE" and fnid:
            source_funcs.setdefault(fnid, []).append(e)
        elif e["type"].startswith("SINK_") and fnid:
            sink_funcs.setdefault(fnid, []).append(e)
        elif e["type"] == "ROUTE" and fnid:
            route_funcs[fnid] = e
        elif e["type"] == "VALIDATION" and fnid:
            validation_funcs.setdefault(fnid, []).append(e)
        elif e["type"] in ("AUTH_MIDDLEWARE", "AUTH_CHECK", "JWT_SIGN", "JWT_VERIFY") and fnid:
            auth_funcs.setdefault(fnid, []).append(e)

    call_graph = {}
    for fnid, info in known_funcs.items():
        callees = _get_callees(info.get("calls", []), known_funcs)
        if callees:
            call_graph[fnid] = callees

    # Store taint paths if we use the taint runner
    build_security_graph.taint_paths = []

    if ast_data:
        from taint import TaintRunner
        runner = TaintRunner(ast_data, entities, known_funcs)
        taint_paths = runner.run()
        build_security_graph.taint_paths = taint_paths

        flows = []
        for flow_id, path in enumerate(taint_paths):
            path_labels = [path.source.name] + [e.to_var for e in path.edges] + [path.sink_call]
            full_path = [f"{path.source.file}::{path.source.name}"] + [f"{e.file}::{e.to_var}" for e in path.edges]

            flows.append({
                "id": f"flow-{flow_id}",
                "source": path.source.name,
                "source_fnid": f"{path.source.file}::{path.source.name}",
                "sink": path.sink_call,
                "sink_fnid": f"{path.source.file}::{path.sink_call}",
                "sink_type": path.sink_type,
                "path": full_path,
                "path_labels": path_labels,
                "validated": path.sanitized,
                "validators": path.sanitizers,
                "expressions": [e.expression for e in path.edges]
            })
    else:
        # Fallback to function-level call-graph traversal
        def find_flow_paths(source_fnid, visited=None):
            if visited is None:
                visited = set()
            if source_fnid in visited:
                return []
            visited.add(source_fnid)

            paths = []
            callees = call_graph.get(source_fnid, set())

            for callee in callees:
                if callee in sink_funcs:
                    for s in sink_funcs[callee]:
                        has_val = bool(validation_funcs.get(source_fnid) or validation_funcs.get(callee))
                        val_labels = []
                        for vfnid in (source_fnid, callee):
                            for v in validation_funcs.get(vfnid, []):
                                val_labels.append(v["label"])
                        paths.append({
                            "source_fnid": source_fnid,
                            "intermediate": [callee] if callee != source_fnid else [],
                            "sink_fnid": callee,
                            "sink": s,
                            "validated": has_val or bool(val_labels),
                            "validators": val_labels,
                        })

                if callee not in visited:
                    sub_paths = find_flow_paths(callee, visited.copy())
                    for sp in sub_paths:
                        sp["intermediate"] = [callee] + sp.get("intermediate", [])
                        paths.append(sp)

            return paths

        flows = []
        flow_id = 0
        for src_fnid in source_funcs:
            flow_paths = find_flow_paths(src_fnid)
            for fp in flow_paths:
                for se in source_funcs[src_fnid]:
                    full_path = [src_fnid] + fp.get("intermediate", []) + [fp["sink_fnid"]]
                    path_labels = []
                    for pid in full_path:
                        if pid in known_funcs:
                            path_labels.append(known_funcs[pid]["name"])
                        elif pid in route_funcs:
                            path_labels.append(route_funcs[pid]["label"])
                        else:
                            path_labels.append(pid.split("::")[-1])

                    flows.append({
                        "id": f"flow-{flow_id}",
                        "source": se["label"],
                        "source_fnid": src_fnid,
                        "sink": fp["sink"]["label"],
                        "sink_fnid": fp["sink_fnid"],
                        "sink_type": fp["sink"]["type"],
                        "path": full_path,
                        "path_labels": path_labels,
                        "validated": fp["validated"],
                        "validators": fp.get("validators", []),
                    })
                    flow_id += 1

    auth_graph = _build_auth_graph(route_funcs, auth_funcs, known_funcs, call_graph)
    db_graph = _build_db_graph(flows, known_funcs)
    network_graph = _build_network_graph(entities, known_funcs, call_graph)

    return {
        "flows": flows,
        "subgraphs": {
            "auth": auth_graph,
            "database": db_graph,
            "network": network_graph,
        },
        "summary": _build_summary(flows, route_funcs, auth_funcs, entities),
    }

def _build_auth_graph(route_funcs, auth_funcs, known_funcs, call_graph):
    protected = []
    unprotected = []
    auth_chain = []

    for rfnid, route in route_funcs.items():
        callees = call_graph.get(rfnid, set())
        has_auth = False
        auth_at = None
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
            auth_chain.append({
                "route": route["label"],
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

def _build_network_graph(entities, known_funcs, call_graph):
    net_entities = [e for e in entities if e["type"] == "SINK_NETWORK"]
    net_ops = []
    for e in net_entities:
        fnid = e.get("fnid", "")
        fn_name = known_funcs[fnid]["name"] if fnid in known_funcs else "?"
        net_ops.append({
            "function": fn_name,
            "call": e["label"],
            "file": e["file"],
            "line": e["line"],
        })
    return {"operations": net_ops, "total": len(net_ops)}

def _build_summary(flows, route_funcs, auth_funcs, entities):
    by_sink = {}
    for f in flows:
        st = f["sink_type"]
        by_sink[st] = by_sink.get(st, 0) + 1

    total_sources = len([e for e in entities if e["type"] == "SOURCE"])
    total_sinks = len([e for e in entities if e["type"].startswith("SINK_")])
    total_routes = len(route_funcs)
    unvalidated = len([f for f in flows if not f["validated"]])

    return {
        "total_sources": total_sources,
        "total_sinks": total_sinks,
        "total_routes": total_routes,
        "total_flows": len(flows),
        "unvalidated_flows": unvalidated,
        "flows_by_sink_type": by_sink,
    }

def show_security_graph_summary(sg):
    s = sg["summary"]
    print(f"  {DIM}[*]{RST} security graph:")
    print(f"    {GRN}•{RST} {s['total_sources']} sources, {s['total_sinks']} sinks, {s['total_routes']} routes")
    print(f"    {GRN}•{RST} {s['total_flows']} data-flow paths ({s['unvalidated_flows']} unvalidated)")
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
