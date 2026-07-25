"""
Symbol resolver for the IR pipeline.

Takes all IRModules from a project and:
  1. Builds a global function index (name → functions across all files)
  2. Resolves each IRCall to its possible function definitions
  3. Traces receiver expressions to infer types (prisma.user → PrismaClient)
  4. Populates call_resolutions on each module
"""

from typing import Optional
from ir import IRModule, IRFunction, IRCall, IRAssign, IRBranch, IRReturn, IRCallExpr, IRVar, IRAccess


class SymbolTable:
    """Global index of functions, imports, and known types across all modules."""

    def __init__(self):
        # name.lower() → list of (file_path, function_id)
        self.functions: dict[str, list[tuple[str, str]]] = {}
        # file_path → { local_name → (source_module, exported_name) }
        self.imports: dict[str, dict[str, tuple[str, str]]] = {}
        # Known framework type patterns
        self.known_types: dict[str, str] = {
            "prisma": "PRISMA_CLIENT",
            "req": "EXPRESS_REQUEST",
            "request": "EXPRESS_REQUEST",
            "res": "EXPRESS_RESPONSE",
            "response": "EXPRESS_RESPONSE",
            "event": "AWS_LAMBDA_EVENT",
            "ctx": "AWS_LAMBDA_CONTEXT",
            "fs": "FS_MODULE",
            "path": "PATH_MODULE",
            "child_process": "CHILD_PROCESS",
            "axios": "AXIOS",
        }
        # file_path → { var_name → type_string }
        self.locals: dict[str, dict[str, str]] = {}

    def build(self, modules: list[IRModule]):
        """Index all functions and imports across modules."""
        for mod in modules:
            fp = mod.file_path.replace("\\", "/")
            for fn in mod.functions:
                key = fn.name.lower()
                self.functions.setdefault(key, []).append((fp, fn.id))

    def resolve_call(self, call: IRCall, mod: IRModule) -> tuple[Optional[str], list[str], float]:
        """Resolve an IRCall to its most likely target."""
        target = call.target.lower()

        # 1. Exact match in global index
        candidates = self.functions.get(target, [])
        if candidates:
            best = candidates[0][1]
            return best, [c[1] for c in candidates], 1.0

        # 2. Try with receiver type hint
        if call.receiver:
            rtype = self._resolve_receiver_type(call.receiver, mod)
            if rtype:
                qualified = f"{rtype}.{target}"
                qualified_fns = self.functions.get(qualified.lower(), [])
                if qualified_fns:
                    best = qualified_fns[0][1]
                    return best, [c[1] for c in qualified_fns], 0.9

            # 3. Try as module.function
            receiver_text = self._expr_to_text(call.receiver)
            qualified = f"{receiver_text}.{call.target}"
            qualified_fns = self.functions.get(qualified.lower(), [])
            if qualified_fns:
                best = qualified_fns[0][1]
                return best, [c[1] for c in qualified_fns], 0.85

        return None, [], 0.0

    def _resolve_receiver_type(self, expr, mod: IRModule) -> Optional[str]:
        """Infer the type of a receiver expression."""
        if isinstance(expr, IRVar):
            name = expr.name.lower()
            # Check known types
            if name in self.known_types:
                return self.known_types[name]
            # Check imports in this module
            mod_path = mod.file_path.replace("\\", "/")
            mod_imports = self.imports.get(mod_path, {})
            if name in mod_imports:
                src_mod, exported = mod_imports[name]
                return f"IMPORT:{src_mod}:{exported}"
            # Check local type hints from assignments
            mod_locals = self.locals.get(mod_path, {})
            if name in mod_locals:
                return mod_locals[name]
        elif isinstance(expr, IRAccess):
            # For prisma.user, the root might be a known type
            return self._resolve_receiver_type(expr.root, mod)
        return None

    @staticmethod
    def _expr_to_text(expr) -> str:
        """Get approximate text of an expression for matching."""
        if isinstance(expr, IRVar):
            return expr.name
        elif isinstance(expr, IRAccess):
            parts = [SymbolTable._expr_to_text(expr.root)]
            parts.extend(str(p) if isinstance(p, str) else SymbolTable._expr_to_text(p) for p in expr.path)
            return ".".join(parts)
        return ""


class SymbolResolver:
    """Runs symbol resolution on a list of IRModules."""

    def __init__(self, modules: list[IRModule]):
        self.modules = modules
        self.table = SymbolTable()

    def resolve_all(self):
        """Complete resolution pass across all modules."""
        self.table.build(self.modules)
        for mod in self.modules:
            for fn in mod.functions:
                self._resolve_function(fn, mod)

    def _resolve_function(self, fn: IRFunction, mod: IRModule):
        for stmt in fn.body:
            self._resolve_stmt(stmt, mod)

    def _resolve_stmt(self, stmt, mod: IRModule):
        if isinstance(stmt, IRCall):
            self._resolve_call(stmt, mod)
        elif isinstance(stmt, IRBranch):
            for s in stmt.true_body:
                self._resolve_stmt(s, mod)
            for s in stmt.false_body:
                self._resolve_stmt(s, mod)
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                self._resolve_expr(stmt.value, mod)
        elif isinstance(stmt, IRAssign):
            if stmt.value:
                self._resolve_expr(stmt.value, mod)

    def _resolve_call(self, stmt, mod: IRModule):
        resolved_fn_id, candidates, conf = self.table.resolve_call(stmt, mod)
        if resolved_fn_id or candidates:
            mod.add_resolution(
                call_id=stmt.id,
                resolved_fn_id=resolved_fn_id,
                candidates=candidates,
                confidence=conf,
            )

    def _resolve_expr(self, expr, mod: IRModule):
        if isinstance(expr, IRCallExpr):
            resolved_fn_id, candidates, conf = self.table.resolve_call(expr, mod)
            if resolved_fn_id or candidates:
                mod.add_resolution(
                    call_id=expr.id,
                    resolved_fn_id=resolved_fn_id,
                    candidates=candidates,
                    confidence=conf,
                )
            for arg in expr.args:
                self._resolve_expr(arg, mod)
            if expr.receiver:
                self._resolve_expr(expr.receiver, mod)
        elif isinstance(expr, IRAccess):
            self._resolve_expr(expr.root, mod)
