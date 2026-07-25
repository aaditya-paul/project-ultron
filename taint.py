from dataclasses import dataclass, field
import re
import os
from typing import List, Dict, Set, Optional, Tuple
from colors import DIM, RST, YLW, GRN, CYAN, RED


@dataclass
class TaintedVar:
    name: str           # "username", "req.body.email"
    file: str
    line: int
    source_label: str   # Original source
    sanitized: bool = False
    sanitizers: List[str] = field(default_factory=list)

@dataclass
class TaintEdge:
    from_var: str
    to_var: str
    edge_type: str      # "assignment" | "arg_pass" | "return" | "field_access"
    file: str
    line: int
    expression: str     # Raw text of transformation

@dataclass
class TaintPath:
    source: TaintedVar
    sink_call: str
    sink_type: str
    edges: List[TaintEdge]
    sanitized: bool
    sanitizers: List[str]
    confidence: float

def references_var(expr: str, var_name: str) -> bool:
    if not expr or not var_name:
        return False
    escaped = re.escape(var_name)
    # Match as a word/subsegment ensuring it isn't part of a larger identifier
    pattern = r'(?<![a-zA-Z0-9_])' + escaped + r'(?![a-zA-Z0-9_])'
    return bool(re.search(pattern, expr))

class TaintRunner:
    def __init__(self, ast_data, entities, known_funcs):
        self.ast_data = ast_data
        self.entities = entities
        self.known_funcs = known_funcs
        
        # Maps fnid -> list of FunctionFeatures or parsed function dictionary
        # We can map fnid -> function parsed dict
        self.func_defs = {}
        for fpath, info in ast_data.get("files", {}).items():
            for fn in info.get("functions", []):
                fnid = f"{fpath}::{fn.get('name', 'anonymous')}"
                self.func_defs[fnid] = fn

        # Taint state: fnid -> dict of {var_name: TaintedVar}
        self.tainted_in_fn = {}
        # Taint edges recorded: list of TaintEdge
        self.edges = []
        # Detected flows: list of TaintPath
        self.detected_paths = []
        # Track functions currently in propagation stack to prevent recursion loops
        self.visited_fns = set()
        # Track if function returns a tainted value: fnid -> (is_tainted, source_lbl, sanitizers)
        self.fn_return_taint = {}

    def run(self) -> List[TaintPath]:
        self.detected_paths = []
        self.edges = []
        self.tainted_in_fn = {}
        self.visited_fns = set()
        self.fn_return_taint = {}

        # 1. Seed taint from SOURCE entities
        sources = [e for e in self.entities if e["type"] == "SOURCE"]
        for src in sources:
            fnid = src["fnid"]
            var_name = src["label"]
            # If label is "param:foo", extract "foo"
            if var_name.startswith("param:"):
                var_name = var_name[6:]
                
            t_var = TaintedVar(
                name=var_name,
                file=src["file"],
                line=src["line"],
                source_label=src["label"]
            )
            self.tainted_in_fn.setdefault(fnid, {})[var_name] = t_var

        # 2. Propagate taint for each function containing a seed or source
        for fnid in list(self.tainted_in_fn.keys()):
            self._propagate_function(fnid)

        return self.detected_paths

    def _propagate_function(self, fnid: str):
        if fnid in self.visited_fns:
            return
        self.visited_fns.add(fnid)

        fn_def = self.func_defs.get(fnid)
        if not fn_def:
            self.visited_fns.remove(fnid)
            return

        fpath = fnid.split("::")[0]
        file_info = self.ast_data["files"].get(fpath, {})
        start_line = fn_def["line"]
        end_line = fn_def.get("end_line", start_line)

        # Collect events in line order
        assignments = [a for a in file_info.get("assignments", []) if start_line <= a["line"] <= end_line]
        returns = [r for r in file_info.get("returns", []) if start_line <= r["line"] <= end_line]
        calls = [c for c in file_info.get("calls", []) if start_line <= c["line"] <= end_line]

        events = []
        for a in assignments:
            events.append(("assign", a["line"], a))
        for r in returns:
            events.append(("return", r["line"], r))
        for c in calls:
            events.append(("call", c["line"], c))

        # Sort events by line number to simulate execution flow
        events.sort(key=lambda x: x[1])

        # Active tainted variables in this function's scope
        active_taint = self.tainted_in_fn.setdefault(fnid, {})

        # Find sanitizers and sinks in this function
        fn_validations = []
        for e in self.entities:
            if e["fnid"] == fnid and e["type"] == "VALIDATION":
                fn_validations.append(e)

        fn_sinks = []
        for e in self.entities:
            if e["fnid"] == fnid and e["type"] in ("SINK_DATABASE", "SINK_SQL", "SINK_SHELL", "SINK_FILE", "SINK_NETWORK"):
                fn_sinks.append(e)

        for etype, line, data in events:
            debug = os.environ.get("ULTRON_DEBUG") == "1"
            if etype == "assign":
                target = data["target"]
                val = data["value_text"]
                
                # Check if this assignment references any tainted variable
                referenced_taints = []
                for tvar_name, tvar in list(active_taint.items()):
                    if references_var(val, tvar_name):
                        referenced_taints.append(tvar)

                # Also check if this assignment is calling a function that returns tainted data
                # E.g. x = fetchFromDb() where fetchFromDb is known to return taint
                for called_fnid, ret_info in self.fn_return_taint.items():
                    called_fn_name = called_fnid.split("::")[-1]
                    if references_var(val, called_fn_name):
                        # Construct a mock tainted variable source
                        mock_tvar = TaintedVar(
                            name=called_fn_name,
                            file=fpath,
                            line=line,
                            source_label=ret_info[1]
                        )
                        if ret_info[2]: # sanitizers
                            mock_tvar.sanitized = True
                            mock_tvar.sanitizers = list(ret_info[2])
                        referenced_taints.append(mock_tvar)

                if referenced_taints:
                    # Target is now tainted!
                    # Inherit sanitization from inputs
                    is_sanitized = all(t.sanitized for t in referenced_taints)
                    sanitizers = []
                    for t in referenced_taints:
                        sanitizers.extend(t.sanitizers)

                    # Check if val is passed through a local validator function
                    for val_ent in fn_validations:
                        if references_var(val, val_ent["label"]) or references_var(val, "validate") or references_var(val, "sanitize"):
                            is_sanitized = True
                            sanitizers.append(val_ent["label"])

                    new_tvar = TaintedVar(
                        name=target,
                        file=fpath,
                        line=line,
                        source_label=referenced_taints[0].source_label,
                        sanitized=is_sanitized,
                        sanitizers=list(set(sanitizers))
                    )
                    active_taint[target] = new_tvar
                    
                    if debug:
                        san_lbl = f" {GRN}(sanitized via {sanitizers}){RST}" if is_sanitized else ""
                        print(f"  {DIM}[DEBUG] Taint: {fpath}:{line} -> Tainted variable '{target}' from '{referenced_taints[0].name}'{san_lbl}{RST}")

                    # Record edges
                    for parent in referenced_taints:
                        edge = TaintEdge(
                            from_var=parent.name,
                            to_var=target,
                            edge_type="assignment",
                            file=fpath,
                            line=line,
                            expression=val
                        )
                        self.edges.append(edge)
                else:
                    # Kill-set: Reassignment to untainted value removes taint
                    if target in active_taint:
                        if debug:
                            print(f"  {DIM}[DEBUG] Taint: {fpath}:{line} -> Killed taint on variable '{target}' (reassignment to untainted){RST}")
                        del active_taint[target]

            elif etype == "call":
                call_text = data["text"]
                
                # Check if this call is a sink
                sink_info = self._get_sink_type_for_call(call_text, fpath)
                if sink_info:
                    sink_type, confidence = sink_info
                    # Check if call references any tainted variable
                    for tvar_name, tvar in active_taint.items():
                        if references_var(call_text, tvar_name):
                            if debug:
                                san_lbl = f" {GRN}[SANITIZED via {tvar.sanitizers}]{RST}" if tvar.sanitized else f" {RED}[UNSANITIZED]{RST}"
                                print(f"  {YLW}[DEBUG] Taint Sink Reached: {fpath}:{line} -> Tainted variable '{tvar.name}' reached sink '{call_text}' ({sink_type}){san_lbl}{RST}")
                            # Reached a sink! Construct the TaintPath
                            path_edges = self._trace_edges(tvar.name, fpath, fnid)
                            
                            # Resolve the root source variable
                            root_var_name = tvar.name
                            if path_edges:
                                root_var_name = path_edges[0].from_var
                            
                            root_source = self.tainted_in_fn.get(fnid, {}).get(root_var_name)
                            if not root_source:
                                root_source = TaintedVar(
                                    name=root_var_name,
                                    file=fpath,
                                    line=start_line,
                                    source_label=tvar.source_label
                                )

                            path = TaintPath(
                                source=root_source,
                                sink_call=call_text,
                                sink_type=sink_type,
                                edges=path_edges,
                                sanitized=tvar.sanitized,
                                sanitizers=tvar.sanitizers,
                                confidence=confidence
                            )
                            self.detected_paths.append(path)

                # 2. Interprocedural Call Propagation
                # Extract called function name
                if "(" in call_text:
                    called_name = call_text.split("(")[0].strip().split(".")[-1].split()[-1]
                else:
                    called_name = call_text.strip().split(".")[-1]

                # Resolve targets
                for target_fnid, target_fn_def in self.func_defs.items():
                    target_name = target_fnid.split("::")[-1]
                    if target_name.lower() == called_name.lower():
                        # We have a candidate called function. Map arguments!
                        # Extract arguments from call text (e.g. B(x, y) -> args: ["x", "y"])
                        args_match = re.search(r'\((.*)\)', call_text)
                        if args_match:
                            args = [a.strip() for a in args_match.group(1).split(",")]
                            params = target_fn_def.get("params", [])
                            
                            # Find if any arguments are tainted
                            for idx, arg in enumerate(args):
                                for tvar_name, tvar in active_taint.items():
                                    if references_var(arg, tvar_name) and idx < len(params):
                                        param_name = params[idx]
                                        # Mark parameter as tainted in target function's scope
                                        target_active = self.tainted_in_fn.setdefault(target_fnid, {})
                                        target_active[param_name] = TaintedVar(
                                            name=param_name,
                                            file=target_fn_def.get("file", target_fnid.split("::")[0]),
                                            line=target_fn_def["line"],
                                            source_label=tvar.source_label,
                                            sanitized=tvar.sanitized,
                                            sanitizers=list(tvar.sanitizers)
                                        )
                                        if debug:
                                            print(f"  {DIM}[DEBUG] Taint: {fpath}:{line} -> Interprocedural arg pass: '{tvar.name}' -> parameter '{param_name}' of '{target_name}'{RST}")
                                        # Record arg_pass edge
                                        edge = TaintEdge(
                                            from_var=tvar.name,
                                            to_var=param_name,
                                            edge_type="arg_pass",
                                            file=fpath,
                                            line=line,
                                            expression=call_text
                                        )
                                        self.edges.append(edge)
                                        
                                        # Propagate the target function recursively
                                        self._propagate_function(target_fnid)

            elif etype == "return":
                val = data["value_text"]
                # If the returned value references a tainted variable, mark this function as returning taint!
                for tvar_name, tvar in active_taint.items():
                    if references_var(val, tvar_name):
                        self.fn_return_taint[fnid] = (True, tvar.source_label, tvar.sanitizers)
                        if debug:
                            print(f"  {DIM}[DEBUG] Taint: {fpath}:{line} -> Function '{fn_def['name']}' returns tainted expression referencing '{tvar_name}'{RST}")
                        # Record return edge
                        edge = TaintEdge(
                            from_var=tvar_name,
                            to_var=f"return:{fn_def['name']}",
                            edge_type="return",
                            file=fpath,
                            line=line,
                            expression=val
                        )
                        self.edges.append(edge)
                        break

        self.visited_fns.remove(fnid)

    def _trace_edges(self, target_var: str, file: str, fnid: str) -> List[TaintEdge]:
        # Walk backward from target_var to trace the flow paths
        path_edges = []
        curr = target_var
        visited = set()
        
        while curr:
            if curr in visited:
                break
            visited.add(curr)
            
            # Find the latest edge that wrote to curr in this file
            parent_edge = None
            for edge in reversed(self.edges):
                if edge.file == file and edge.to_var == curr:
                    parent_edge = edge
                    break
            
            if parent_edge:
                path_edges.insert(0, parent_edge)
                curr = parent_edge.from_var
            else:
                curr = None
                
        return path_edges

    def _get_sink_type_for_call(self, call_text: str, fpath: str) -> Optional[Tuple[str, float]]:
        # 1. Check if it targets a classified user-defined function in our repo
        if "(" in call_text:
            called_name = call_text.split("(")[0].strip().split(".")[-1].split()[-1]
        else:
            called_name = call_text.strip().split(".")[-1]
            
        for target_fnid in self.func_defs:
            target_name = target_fnid.split("::")[-1]
            if target_name.lower() == called_name.lower():
                # Look up if this function is classified as a SINK in entities
                for e in self.entities:
                    if e["fnid"] == target_fnid and e["type"].startswith("SINK_"):
                        return e["type"], e["metadata"].get("confidence", 0.80)
                        
        # 2. Heuristic: Check third-party library patterns
        from classifier import matches_any_glob, SINK_DB_PATTERNS, SINK_SHELL_PATTERNS, SINK_FILE_PATTERNS, SINK_NETWORK_PATTERNS
        
        if matches_any_glob(call_text, SINK_SHELL_PATTERNS):
            return "SINK_SHELL", 0.90
        if matches_any_glob(call_text, SINK_DB_PATTERNS):
            return "SINK_DATABASE", 0.85
        if matches_any_glob(call_text, SINK_FILE_PATTERNS):
            return "SINK_FILE", 0.85
        if matches_any_glob(call_text, SINK_NETWORK_PATTERNS):
            return "SINK_NETWORK", 0.85
            
        return None
