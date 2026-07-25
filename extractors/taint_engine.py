
"""
IR-based taint engine.

Uses IR data (provenance edges, semantic tags, call resolutions) to detect
data-flow paths from sources to sinks, with inter-procedural propagation
and sanitizer (VALIDATION_GATE) awareness.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Optional
import fnmatch

from ir import IRModule, IRFunction, IRCall, IRAssign, IRBranch, IRReturn, IRCallExpr, IRAccess, IRVar, Edge, Tag
from extractors.call_graph import CallGraph


# ── Sink patterns (mirrors classifier.py) ────────────────────────────────────

# ── Sink patterns (mirrors classifier.py) ────────────────────────────────────

SINK_DB_PATTERNS = {
    "*db.query*", "*db.raw*", "*db.execute*", "*db.executesql*",
    "*prisma*", "*knex*", "*mongoose*", "*sequelize*",
    "*$transaction*", "*$execute*", "*$queryrawunsafe*", "*sql.raw*",
    "*.findunique*", "*.findmany*", "*.findfirst*", "*.findone*", "*.findbyid*", "*.findbypk*",
    "*.createmany*", "*.updatemany*", "*.deletemany*", "*.upsert*", "*.executesql*",
    "*.insert*", "*$where*", "*mapreduce*", "queryresulttojson",
    "db.query", "db.execute", "db.insert", "db.update", "db.delete",
}

EXCLUDED_METHOD_NAMES = {
    # JS/TS Built-ins & Arrays/Objects
    "find", "filter", "map", "foreach", "reduce", "some", "every",
    "includes", "indexof", "create", "assign", "keys", "values",
    "parse", "stringify", "slice", "splice", "push", "pop", "shift", "unshift",
    "split", "join", "format", "replace", "concat", "match", "substring", "trim",
    
    # WebGL / 3D Math / Graphics / Vector & Matrix ops
    "normalize", "sub", "transform", "settransform", "uniform1f", "uniform1i",
    "uniform2f", "uniform3f", "uniform4f", "uniform1fv", "uniform2fv", "uniform3fv",
    "uniform4fv", "uniform1iv", "uniform3iv", "uniformmatrix3fv", "uniformmatrix4fv",
    "computemorphnormals", "getnormalmatrix", "bufferguessnormaltype",
    "refreshuniformsfog", "refreshuniformslights", "refreshuniformscommon",
    "refreshuniformsline", "refreshuniformsdash", "refreshuniformsparticle",
    "refreshuniformsphong", "refreshuniformslambert", "refreshuniformsshadow",
    "loaduniformsgeneric", "loaduniformsmatrices",
    
    # DOM / UI Methods & Components
    "queryselector", "queryselectorall", "getelementbyid", "getelementsbyclassname",
    "getelementsbytagname", "fromqueryparams", "geterrormessage", "streamtext",
    "checkifllmmodelavailable", "buildsystemprompt",
}

SINK_SHELL_PATTERNS = {
    "*child_process*", "*execsync*", "*execfile*", "*popen*", "*system*", "eval", "spawn", "exec"
}

SINK_FILE_PATTERNS = {
    "*readfile*", "*writefile*", "*openfile*", "*unlink*", "*readdir*", "*fs.*",
    "*sendfile*", "*download*", "*createreadstream*", "*createwritestream*"
}

SINK_NETWORK_PATTERNS = {
    "*fetch*", "*axios*", "*ajax*", "*http.*", "*https.*", "*got*", "*superagent*",
    "*undici*"
}

SINK_XSS_PATTERNS = {
    "*dangerouslysetinnerhtml*", "*innerhtml*", "*outerhtml*", "*document.write*", "*res.send*", "*res.write*", "*res.render*"
}

SOURCE_TAG_KINDS = {
    "HTTP_BODY", "HTTP_PARAMS", "FILE_READ", "ENV_VAR", "COOKIE", "AUTH_HEADER",
    "SOURCE_HTTP_BODY", "SOURCE_URL_PARAM", "SOURCE_URL_QUERY", "SOURCE_SESSION", "SOURCE_ENV",
}

OP_TAG_KINDS = {
    "OP_COERCION", "OP_VALIDATION", "OP_AUTH",
}

SINK_TAG_KINDS = {
    "SQL_QUERY", "SHELL_EXEC", "FILE_ACCESS", "NETWORK_CALL", "XSS_OUTPUT"
}


def matches_any_glob(text: str, patterns: set) -> bool:
    text_lower = text.lower()
    for pat in patterns:
        if fnmatch.fnmatch(text_lower, pat.lower()):
            return True
    return False


def is_non_runtime_file(file_path: str) -> bool:
    if not file_path:
        return False
    fp = file_path.replace("\\", "/").lower()
    fn = os.path.basename(fp)
    if any(p in fp for p in ("/cypress/", "/test/", "/tests/", "/__tests__/", "/spec/", "/specs/", "/assets/private/", "/node_modules/", "/vendor/", "/dist/", "/codefixes/", "/data/static/", "/static/codefixes/")):
        return True
    if any(fn.endswith(ext) for ext in (".spec.ts", ".spec.js", ".test.ts", ".test.js", ".min.js", ".bundle.js")):
        return True
    if fn in ("gruntfile.js", "gulpfile.js", "cypress.config.ts", "cypress.config.js", "jest.config.js", "webpack.config.js", "vite.config.ts"):
        return True
    return False


def detect_sink_type(call_target: str) -> Optional[tuple[str, float]]:
    """Check if a call target matches any known sink pattern."""
    target_lower = call_target.lower().strip()
    parts = target_lower.split(".")
    method_name = parts[-1]

    # Exclude non-sink methods unless explicitly called on DB/ORM targets
    if method_name in EXCLUDED_METHOD_NAMES and parts[0] not in ("db", "prisma", "knex", "repo", "repository", "sequelize", "mongoose"):
        return None

    if matches_any_glob(call_target, SINK_SHELL_PATTERNS):
        return ("SINK_SHELL", 0.90)
    if matches_any_glob(call_target, SINK_DB_PATTERNS):
        return ("SINK_DATABASE", 0.85)
    if matches_any_glob(call_target, SINK_FILE_PATTERNS):
        return ("SINK_FILE", 0.85)
    if matches_any_glob(call_target, SINK_XSS_PATTERNS):
        return ("SINK_XSS", 0.85)
    if matches_any_glob(call_target, SINK_NETWORK_PATTERNS):
        return ("SINK_NETWORK", 0.85)
    return None


# ── Taint path data model ────────────────────────────────────────────────────

@dataclass
class TaintPath:
    source_tag: str                # "SOURCE_HTTP_BODY"
    source_node_id: str            # Node ID of the source
    sink_target: str               # "db.query"
    sink_node_id: str              # Node ID of the sink call
    path_node_ids: list[str]       # Ordered from source → sink
    file_path: str = ""
    sanitized: bool = False
    sanitizer_node_ids: list[str] = field(default_factory=list)
    operation_tags: list[str] = field(default_factory=list)  # OP_COERCION, OP_VALIDATION, OP_AUTH
    confidence: float = 1.0
    sink_type: str = "SINK_UNKNOWN"


def expr_to_text(expr) -> str:
    if isinstance(expr, IRVar):
        return expr.name
    elif isinstance(expr, IRAccess):
        parts = [expr_to_text(expr.root)]
        parts.extend(str(p) if isinstance(p, str) else expr_to_text(p) for p in expr.path)
        return ".".join(parts)
    return ""


# ── Taint engine ─────────────────────────────────────────────────────────────

class TaintEngine:
    """IR-based taint analysis with backward propagation."""

    def __init__(self, modules: list[IRModule], call_graph: CallGraph):
        self.modules = modules
        self.call_graph = call_graph

        # Pre-built indexes
        self._node_id_to_fn: dict[str, IRFunction] = {}
        self._fn_id_to_module: dict[str, IRModule] = {}
        self._call_id_to_resolved_fn: dict[str, str] = {}  # call_node_id → fn_id
        self._source_nodes: dict[str, Tag] = {}             # node_id → Tag
        self._sanitizer_nodes: dict[str, Tag] = {}          # node_id → Tag (VALIDATION_GATE)
        self._op_tag_nodes: dict[str, list[str]] = {}       # node_id → [OP_COERCION, ...]
        self._all_edges: list[Edge] = []
        self._edges_by_file: dict[str, list[Edge]] = {}     # file_path → edges
        self._incoming_by_file: dict[str, dict[str, list[Edge]]] = {} # file_path → {target_id → [Edge]}
        self._outgoing_by_file: dict[str, dict[str, list[Edge]]] = {} # file_path → {source_id → [Edge]}
        self._param_node_ids: set[str] = set()
        self._node_to_fn_cache: dict[str, str] = {}
        self._memo: dict[tuple[str, str], list] = {}
        self._sibling_explored_parents: set[str] = set()    # parent IDs whose siblings have been fully explored

        self._build_indexes()

    def _build_indexes(self):
        # resolved_fn_id → list of (call_node_id, caller_module)
        self._callee_to_calls: dict[str, list[tuple[str, IRModule]]] = {}

        for mod in self.modules:
            fp = mod.file_path
            self._all_edges.extend(mod.provenance_edges)
            self._edges_by_file[fp] = mod.provenance_edges

            inc_map = self._incoming_by_file.setdefault(fp, {})
            out_map = self._outgoing_by_file.setdefault(fp, {})
            for e in mod.provenance_edges:
                inc_map.setdefault(e.target_id, []).append(e)
                out_map.setdefault(e.source_id, []).append(e)

            for tag in mod.semantic_tags:
                if tag.kind in SOURCE_TAG_KINDS:
                    self._source_nodes[tag.node_id] = tag
                elif tag.kind == "VALIDATION_GATE":
                    self._sanitizer_nodes[tag.node_id] = tag
                if tag.kind in OP_TAG_KINDS:
                    self._op_tag_nodes.setdefault(tag.node_id, []).append(tag.kind)

            for fn in mod.functions:
                self._node_id_to_fn[fn.id] = fn
                self._fn_id_to_module[fn.id] = mod
                self._index_fn_nodes(fn, mod)
                for p in fn.params:
                    from ir import IRVar
                    p_var_id = IRVar(p).id
                    self._param_node_ids.add(p_var_id)

            for res in mod.call_resolutions:
                if res.resolved_fn_id:
                    self._call_id_to_resolved_fn[res.call_id] = res.resolved_fn_id
                    self._callee_to_calls.setdefault(res.resolved_fn_id, []).append((res.call_id, mod))

    def run(self) -> list[TaintPath]:
        """Main entry point. Returns all detected taint paths."""
        paths: list[TaintPath] = []
        sinks = self._collect_sinks()
        for idx, (sink_node_id, sink_target, sink_type, file_path) in enumerate(sinks, 1):
            self._sibling_explored_parents.clear()
            result = self._backward_propagate(sink_node_id, file_path)
            if result:
                for source_node_id, path_nodes, sanitized, sanitizers, op_tags in result:
                    source_tag = self._source_nodes.get(source_node_id)
                    if source_tag:
                        paths.append(TaintPath(
                            source_tag=source_tag.kind,
                            source_node_id=source_node_id,
                            sink_target=sink_target,
                            sink_node_id=sink_node_id,
                            path_node_ids=path_nodes,
                            file_path=file_path,
                            sanitized=sanitized,
                            sanitizer_node_ids=sanitizers,
                            operation_tags=op_tags,
                            confidence=0.85 if sanitized else 0.95,
                            sink_type=sink_type,
                        ))

        # Deduplicate by (source_node_id, sink_node_id, file_path)
        seen: set[tuple[str, str, str]] = set()
        unique: list[TaintPath] = []
        for p in paths:
            key = (p.source_node_id, p.sink_node_id, p.file_path)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique

    # ── Sink collection ───────────────────────────────────────────────────

    def _collect_sinks(self) -> list[tuple[str, str, str, str]]:
        """Find all sink nodes across all modules.
        Returns list of (node_id, call_target, sink_type, file_path).
        """
        sinks = []
        for mod in self.modules:
            if is_non_runtime_file(mod.file_path):
                continue
            for fn in mod.functions:
                self._collect_stmt_sinks(fn.body, mod.file_path, sinks)
        seen: set[tuple[str, str]] = set()
        deduped = []
        for s in sinks:
            key = (s[0], s[3])  # (node_id, file_path)
            if key not in seen:
                seen.add(key)
                deduped.append(s)
        return deduped

    def _collect_stmt_sinks(self, stmts: list, file_path: str, acc: list):
        if is_non_runtime_file(file_path):
            return
        for stmt in stmts:
            if isinstance(stmt, IRCall):
                target_str = f"{expr_to_text(stmt.receiver)}.{stmt.target}" if stmt.receiver else stmt.target
                result = detect_sink_type(target_str)
                if result:
                    acc.append((stmt.id, target_str, result[0], file_path))
                for arg in stmt.args:
                    self._collect_expr_sinks(arg, acc, file_path)
                if stmt.receiver:
                    self._collect_expr_sinks(stmt.receiver, acc, file_path)
            elif isinstance(stmt, IRAssign):
                self._collect_expr_sinks(stmt.value, acc, file_path)
            elif isinstance(stmt, IRBranch):
                self._collect_stmt_sinks(stmt.true_body, file_path, acc)
                self._collect_stmt_sinks(stmt.false_body, file_path, acc)
            elif isinstance(stmt, IRReturn):
                if stmt.value:
                    self._collect_expr_sinks(stmt.value, acc, file_path)

    def _collect_expr_sinks(self, expr, acc: list, file_path: str):
        if is_non_runtime_file(file_path):
            return
        if isinstance(expr, IRCallExpr):
            target_str = f"{expr_to_text(expr.receiver)}.{expr.target}" if expr.receiver else expr.target
            result = detect_sink_type(target_str)
            if result:
                acc.append((expr.id, target_str, result[0], file_path))
            for arg in expr.args:
                self._collect_expr_sinks(arg, acc, file_path)
            if expr.receiver:
                self._collect_expr_sinks(expr.receiver, acc, file_path)
        elif isinstance(expr, IRAccess):
            self._collect_expr_sinks(expr.root, acc, file_path)

    # ── Backward propagation ──────────────────────────────────────────────

    def _backward_propagate(
        self,
        start_node_id: str,
        file_path: str,
        depth: int = 0,
        visited: set | None = None,
        path: list[str] | None = None,
    ) -> list[tuple[str, list[str], bool, list[str], list[str]]]:
        """Walk backward through provenance edges from start_node_id.

        Returns list of (source_node_id, path_node_ids, sanitized, sanitizer_ids, operation_tags).
        """
        if is_non_runtime_file(file_path):
            return []
        memo_key = (start_node_id, file_path)
        if visited is None:
            visited = set()
            if memo_key in self._memo:
                return self._memo[memo_key]
        elif memo_key in self._memo and start_node_id not in visited:
            return self._memo[memo_key]

        if path is None:
            path = [start_node_id]

        if depth > 20:
            return []
        if start_node_id in visited:
            return []
        visited.add(start_node_id)

        results: list[tuple[str, list[str], bool, list[str], list[str]]] = []

        # Collect operation tags for this node (OP_COERCION, OP_VALIDATION, OP_AUTH)
        node_op_tags = self._op_tag_nodes.get(start_node_id, [])

        # Check if this node is a source
        source_tag = self._source_nodes.get(start_node_id)
        if source_tag:
            results.append((start_node_id, list(reversed(path)), False, [], node_op_tags))

        # Check if this node is a sanitizer
        sanitizer_tag = self._sanitizer_nodes.get(start_node_id)
        is_sanitized = sanitizer_tag is not None
        sanitizer_ids = [start_node_id] if sanitizer_tag else []

        # Fast O(1) edge lookup
        inc_map = self._incoming_by_file.get(file_path, {})
        incoming = inc_map.get(start_node_id, [])

        if incoming:
            for edge in incoming:
                src_id = edge.source_id
                new_path = path + [src_id]
                for sub_result in self._backward_propagate(
                    src_id, file_path, depth + 1, visited, new_path
                ):
                    src_id2, p, sanitized_flag, sanitizers, op_tags = sub_result
                    all_sanitizers = sanitizer_ids + sanitizers
                    all_op_tags = list(set(node_op_tags + op_tags))
                    results.append((
                        src_id2, p,
                        is_sanitized or sanitized_flag,
                        all_sanitizers,
                        all_op_tags,
                    ))

        # If edge-based propagation found nothing, try inter-procedural lookups
        if not results:
            # 1. Check if this node (a call node) has a resolution → follow into callee's returns
            resolved_fn_id = self._call_id_to_resolved_fn.get(start_node_id)
            if resolved_fn_id:
                callee_fn = self._node_id_to_fn.get(resolved_fn_id)
                if callee_fn:
                    for sub_result in self._backward_through_callee(
                        callee_fn, file_path, depth + 1, visited, path
                    ):
                        src_id, p, sanitized_flag, sanitizers, op_tags = sub_result
                        all_sanitizers = sanitizer_ids + sanitizers
                        all_op_tags = list(set(node_op_tags + op_tags))
                        results.append((
                            src_id, p,
                            is_sanitized or sanitized_flag,
                            all_sanitizers,
                            all_op_tags,
                        ))

            # 2. Check if this node is a function parameter → walk backward from caller call sites
            if start_node_id in self._param_node_ids:
                fn_id = self._node_id_to_function(start_node_id)
                if fn_id:
                    caller_sites = self._callee_to_calls.get(fn_id, [])
                    for call_node_id, caller_mod in caller_sites:
                        new_path = path + [call_node_id]
                        for sub_result in self._backward_propagate(
                            call_node_id, caller_mod.file_path, depth + 1, visited, new_path
                        ):
                            src_id, p, sanitized_flag, sanitizers, op_tags = sub_result
                            all_sanitizers = sanitizer_ids + sanitizers
                            all_op_tags = list(set(node_op_tags + op_tags))
                            results.append((
                                src_id, p,
                                is_sanitized or sanitized_flag,
                                all_sanitizers,
                                all_op_tags,
                            ))

        visited.discard(start_node_id)
        if results:
            dedup_results = []
            seen_res = set()
            for r in results:
                key = (r[0], r[2])
                if key not in seen_res:
                    seen_res.add(key)
                    dedup_results.append(r)
            results = dedup_results
            self._memo[memo_key] = results
        return results

    def _node_id_to_function(self, node_id: str) -> Optional[str]:
        """Find which function contains a given node ID."""
        return self._node_to_fn_cache.get(node_id)

    def _index_fn_nodes(self, fn: IRFunction, mod: IRModule):
        """Recursively index all node IDs (statements and expressions) in a function."""
        for stmt in fn.body:
            self._index_stmt_nodes(stmt, fn.id)

    def _index_stmt_nodes(self, stmt, fn_id: str):
        """Index a statement and all expression nodes within it."""
        self._node_to_fn_cache[stmt.id] = fn_id
        if isinstance(stmt, IRCall):
            for arg in stmt.args:
                self._index_expr_nodes(arg, fn_id)
            if stmt.receiver:
                self._index_expr_nodes(stmt.receiver, fn_id)
        elif isinstance(stmt, IRAssign):
            if stmt.value:
                self._index_expr_nodes(stmt.value, fn_id)
        elif isinstance(stmt, IRBranch):
            self._index_expr_nodes(stmt.condition, fn_id)
            for s in stmt.true_body:
                self._index_stmt_nodes(s, fn_id)
            for s in stmt.false_body:
                self._index_stmt_nodes(s, fn_id)
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                self._index_expr_nodes(stmt.value, fn_id)

    def _index_expr_nodes(self, expr, fn_id: str):
        """Index an expression node and all its children."""
        self._node_to_fn_cache[expr.id] = fn_id
        if isinstance(expr, IRAccess):
            self._index_expr_nodes(expr.root, fn_id)
            for p in expr.path:
                if isinstance(p, IRAccess):
                    self._index_expr_nodes(p, fn_id)
        elif isinstance(expr, IRCallExpr):
            for arg in expr.args:
                self._index_expr_nodes(arg, fn_id)
            if expr.receiver:
                self._index_expr_nodes(expr.receiver, fn_id)

    def _backward_through_callee(
        self,
        callee_fn: IRFunction,
        file_path: str,
        depth: int,
        visited: set,
        path: list[str],
    ) -> list[tuple[str, list[str], bool, list[str], list[str]]]:
        """When a sink calls a function, walk backward through that function's return values."""
        results = []
        for stmt in callee_fn.body:
            if isinstance(stmt, IRReturn) and stmt.value:
                # The return value contains the source — walk backward from the return
                return_id = stmt.id
                new_path = path + [return_id]
                for sub_result in self._backward_propagate(
                    return_id, file_path, depth + 1, visited, new_path
                ):
                    results.append(sub_result)
            elif isinstance(stmt, IRBranch):
                for s in stmt.true_body:
                    if isinstance(s, IRReturn) and s.value:
                        return_id = s.id
                        new_path = path + [return_id]
                        for sub_result in self._backward_propagate(
                            return_id, file_path, depth + 1, visited, new_path
                        ):
                            results.append(sub_result)
                for s in stmt.false_body:
                    if isinstance(s, IRReturn) and s.value:
                        return_id = s.id
                        new_path = path + [return_id]
                        for sub_result in self._backward_propagate(
                            return_id, file_path, depth + 1, visited, new_path
                        ):
                            results.append(sub_result)
        return results
