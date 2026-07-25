
"""
Call graph built from IR call resolutions.

Provides a directed graph of caller → callee relationships across all modules,
with support for path finding, cycle detection, and serialization.
"""

from typing import Optional
from ir import IRModule, IRFunction, IRCall, IRBranch, IRAssign, IRCallExpr, IRReturn


def _find_stmt_container_id(stmts: list, target_id: str) -> Optional[str]:
    """Find the function ID that contains a given statement ID."""
    for stmt in stmts:
        if stmt.id == target_id:
            return True  # found in this scope
        if isinstance(stmt, IRBranch):
            if _find_stmt_container_id(stmt.true_body, target_id):
                return True
            if _find_stmt_container_id(stmt.false_body, target_id):
                return True
    return False


def _find_fn_for_call(modules: list[IRModule], call_id: str) -> Optional[str]:
    """Find which function ID contains a given call/callexpr ID."""
    for mod in modules:
        for fn in mod.functions:
            if _find_stmt_container_id(fn.body, call_id):
                return fn.id
    return None


def _find_expr_container_id(stmts: list, target_id: str) -> bool:
    """Search statements and their expressions for a matching ID."""
    for stmt in stmts:
        if stmt.id == target_id:
            return True
        if isinstance(stmt, IRAssign) and stmt.value and stmt.value.id == target_id:
            return True
        if isinstance(stmt, IRCall):
            if stmt.id == target_id:
                return True
        if isinstance(stmt, IRBranch):
            if _find_stmt_container_id(stmt.true_body, target_id):
                return True
            if _find_stmt_container_id(stmt.false_body, target_id):
                return True
    return False


class CallGraph:
    """Directed call graph from IR modules."""

    def __init__(self, modules: list[IRModule] | None = None):
        # caller_fn_id → set of callee_fn_id
        self.adjacency: dict[str, set[str]] = {}
        # callee_fn_id → set of caller_fn_id
        self.reverse_adj: dict[str, set[str]] = {}
        # fn_id → (file_path, name)
        self.fn_index: dict[str, tuple[str, str]] = {}
        # call_node_id → resolved_fn_id
        self.call_map: dict[str, str] = {}

        if modules:
            self.build(modules)

    def build(self, modules: list[IRModule]):
        for mod in modules:
            for fn in mod.functions:
                self.fn_index.setdefault(fn.id, (mod.file_path, fn.name))

        # Single-pass O(N) map from call_id -> caller_fn_id
        call_parent_map: dict[str, str] = {}
        for mod in modules:
            for fn in mod.functions:
                self._index_fn_body_calls(fn.body, fn.id, call_parent_map)

        for mod in modules:
            for res in mod.call_resolutions:
                if not res.resolved_fn_id:
                    continue
                self.call_map[res.call_id] = res.resolved_fn_id
                caller_id = call_parent_map.get(res.call_id)
                if caller_id:
                    self._add_edge(caller_id, res.resolved_fn_id)

    def _index_fn_body_calls(self, stmts: list, fn_id: str, call_parent_map: dict):
        for stmt in stmts:
            if hasattr(stmt, 'id'):
                call_parent_map[stmt.id] = fn_id
            if isinstance(stmt, IRCall):
                if stmt.receiver:
                    self._index_expr_calls(stmt.receiver, fn_id, call_parent_map)
                for a in stmt.args:
                    self._index_expr_calls(a, fn_id, call_parent_map)
            elif isinstance(stmt, IRAssign):
                if stmt.value:
                    self._index_expr_calls(stmt.value, fn_id, call_parent_map)
            elif isinstance(stmt, IRBranch):
                if stmt.condition:
                    self._index_expr_calls(stmt.condition, fn_id, call_parent_map)
                self._index_fn_body_calls(stmt.true_body, fn_id, call_parent_map)
                self._index_fn_body_calls(stmt.false_body, fn_id, call_parent_map)
            elif isinstance(stmt, IRReturn):
                if stmt.value:
                    self._index_expr_calls(stmt.value, fn_id, call_parent_map)

    def _index_expr_calls(self, expr, fn_id: str, call_parent_map: dict):
        if not expr:
            return
        if hasattr(expr, 'id'):
            call_parent_map[expr.id] = fn_id
        if hasattr(expr, 'args'):
            for a in expr.args:
                self._index_expr_calls(a, fn_id, call_parent_map)
        if hasattr(expr, 'receiver') and expr.receiver:
            self._index_expr_calls(expr.receiver, fn_id, call_parent_map)

    def _add_edge(self, caller_fn_id: str, callee_fn_id: str):
        self.adjacency.setdefault(caller_fn_id, set()).add(callee_fn_id)
        self.reverse_adj.setdefault(callee_fn_id, set()).add(caller_fn_id)

    def _ensure_node(self, fn_id: str):
        self.adjacency.setdefault(fn_id, set())
        self.reverse_adj.setdefault(fn_id, set())

    def get_callees(self, fn_id: str) -> set[str]:
        return self.adjacency.get(fn_id, set())

    def get_callers(self, fn_id: str) -> set[str]:
        return self.reverse_adj.get(fn_id, set())

    def has_fn(self, fn_id: str) -> bool:
        return fn_id in self.fn_index

    def fn_name(self, fn_id: str) -> str:
        return self.fn_index.get(fn_id, ("", fn_id))[1]

    def fn_file(self, fn_id: str) -> str:
        return self.fn_index.get(fn_id, (fn_id, ""))[0]

    def all_functions(self) -> list[str]:
        return list(self.fn_index.keys())

    def paths_between(self, from_fn_id: str, to_fn_id: str, max_depth: int = 10) -> list[list[str]]:
        """Find all call-chain paths from from_fn_id to to_fn_id (caller→callee)."""
        results = []
        visited = {from_fn_id}

        def dfs(current: str, path: list[str]):
            if current == to_fn_id:
                results.append(list(path))
                return
            if len(path) > max_depth:
                return
            for callee in self.adjacency.get(current, set()):
                if callee not in visited:
                    visited.add(callee)
                    path.append(callee)
                    dfs(callee, path)
                    path.pop()
                    visited.remove(callee)

        dfs(from_fn_id, [from_fn_id])
        return results

    def to_dict(self) -> dict:
        return {
            "adjacency": {k: list(v) for k, v in self.adjacency.items()},
            "reverse_adj": {k: list(v) for k, v in self.reverse_adj.items()},
            "fn_index": {k: list(v) for k, v in self.fn_index.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CallGraph":
        g = cls()
        g.adjacency = {k: set(v) for k, v in data["adjacency"].items()}
        g.reverse_adj = {k: set(v) for k, v in data["reverse_adj"].items()}
        g.fn_index = {k: tuple(v) for k, v in data["fn_index"].items()}
        return g

    def summary(self) -> str:
        fn_count = len(self.fn_index)
        edge_count = sum(len(v) for v in self.adjacency.values())
        return f"CallGraph: {fn_count} functions, {edge_count} call edges"
