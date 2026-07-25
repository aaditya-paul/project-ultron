"""
IR Adapter: converts IRModule into ast_data dict format.

This allows the entire existing pipeline (entities, classifier, security_graph, taint)
to run unchanged on IR-extracted data.

Usage:
  ast_data = parse_repo(target)
  ir_modules = extract_all(target)
  inject_ir_into_ast(ir_modules, ast_data)
  features = extract_features(ast_data)    # works unchanged
"""

from typing import Optional
from ir import (
    IRModule, IRFunction, IRCall, IRVar, IRAccess, IRLiteral,
    IRAssign, IRBranch, IRReturn, IRCallExpr,
)
from features import FunctionFeatures


def inject_ir_into_ast(ir_modules: list[IRModule], ast_data: dict):
    """Replace JS/TS entries in ast_data with IR-derived data."""
    if not ast_data or "files" not in ast_data:
        return

    for mod in ir_modules:
        fpath = mod.file_path.replace("\\", "/")
        file_info = _build_file_info(mod)
        ast_data["files"][fpath] = file_info


def extract_features_from_ir(ir_modules: list[IRModule]) -> list[FunctionFeatures]:
    """Direct conversion from IR to FunctionFeatures (bypasses ast_data)."""
    features = []
    for mod in ir_modules:
        for fn in mod.functions:
            feat = _ir_fn_to_features(fn, mod)
            features.append(feat)
    return features


def _build_file_info(mod: IRModule) -> dict:
    """Convert an IRModule into the ast_data["files"][fpath] dict format."""
    functions = []
    all_calls = []
    all_assigns = []
    all_returns = []
    all_accesses = []

    for fn in mod.functions:
        fn_dict = _ir_fn_to_ast_dict(fn, mod)
        functions.append(fn_dict)

        # Flatten body into parallel lists
        _flatten_body(fn.body, all_calls, all_assigns, all_returns, all_accesses)

    return {
        "language": mod.language,
        "imports": [],
        "functions": functions,
        "calls": all_calls,
        "assignments": all_assigns,
        "returns": all_returns,
        "field_accesses": all_accesses,
    }


def _ir_fn_to_ast_dict(fn: IRFunction, mod: IRModule) -> dict:
    """Convert an IRFunction into the ast_data function dict format."""

    body_lines = []
    for stmt in fn.body:
        line = _stmt_to_text(stmt, indent=0)
        if line:
            body_lines.append(line)

    body_text = "\n".join(body_lines)
    if len(body_text) > 1000:
        body_text = body_text[:1000] + "... [TRUNCATED]"

    max_line = _max_stmt_line(fn.body, fn.line)
    end_line = max(max_line, fn.line + len(fn.body))

    return {
        "name": fn.name,
        "params": fn.params,
        "line": fn.line,
        "end_line": end_line,
        "anonymous": fn.name == "<anonymous>",
        "body_text": body_text,
    }


def _flatten_body(stmts: list, calls: list, assigns: list, returns: list, accesses: list):
    """Walk IR statements and collect into flat lists matching ast_data format."""
    for stmt in stmts:
        line = stmt.line if hasattr(stmt, "line") and stmt.line else 0
        if isinstance(stmt, IRCall):
            calls.append({"text": _call_to_text(stmt), "line": line})
            for arg in stmt.args:
                _collect_accesses(arg, accesses, line)
        elif isinstance(stmt, IRAssign):
            assigns.append({"target": stmt.target, "value_text": _expr_to_text(stmt.value), "line": line})
            _collect_accesses(stmt.value, accesses, line)
            _collect_expr_calls(stmt.value, calls, line)
        elif isinstance(stmt, IRBranch):
            _collect_accesses(stmt.condition, accesses, line)
            _flatten_body(stmt.true_body, calls, assigns, returns, accesses)
            _flatten_body(stmt.false_body, calls, assigns, returns, accesses)
        elif isinstance(stmt, IRReturn):
            value_text = _expr_to_text(stmt.value) if stmt.value else ""
            returns.append({"value_text": value_text, "line": line})


def _max_stmt_line(stmts: list, default: int) -> int:
    """Find the maximum line number across all statements recursively."""
    max_line = default
    for stmt in stmts:
        if hasattr(stmt, "line") and stmt.line:
            max_line = max(max_line, stmt.line)
        if isinstance(stmt, IRBranch):
            max_line = max(max_line, _max_stmt_line(stmt.true_body, default))
            max_line = max(max_line, _max_stmt_line(stmt.false_body, default))
    return max_line


def _stmt_to_text(stmt, indent: int = 0) -> str:
    """Convert an IRStmt to approximate source text."""
    pad = "  " * indent
    if isinstance(stmt, IRCall):
        return f"{pad}{_call_to_text(stmt)};"
    elif isinstance(stmt, IRAssign):
        return f"{pad}const {stmt.target} = {_expr_to_text(stmt.value)};"
    elif isinstance(stmt, IRBranch):
        cond = _expr_to_text(stmt.condition)
        parts = [f"{pad}if ({cond}) {{"]
        for s in stmt.true_body:
            parts.append(_stmt_to_text(s, indent + 1))
        if stmt.false_body:
            parts.append(f"{pad}}} else {{")
            for s in stmt.false_body:
                parts.append(_stmt_to_text(s, indent + 1))
        parts.append(f"{pad}}}")
        return "\n".join(parts)
    elif isinstance(stmt, IRReturn):
        if stmt.value:
            return f"{pad}return {_expr_to_text(stmt.value)};"
        return f"{pad}return;"
    return ""


def _call_to_text(stmt: IRCall) -> str:
    """Reconstruct call text from IRCall."""
    args_text = ", ".join(_expr_to_text(a) for a in stmt.args)
    if stmt.receiver:
        receiver_text = _expr_to_text(stmt.receiver)
        return f"{receiver_text}.{stmt.target}({args_text})"
    return f"{stmt.target}({args_text})"


def _expr_to_text(expr) -> str:
    """Convert an IR expression back to text."""
    if expr is None:
        return ""
    if isinstance(expr, IRVar):
        return expr.name
    elif isinstance(expr, IRLiteral):
        if expr.value_type == "string":
            return f"'{expr.value}'"
        elif expr.value_type == "null":
            return "null"
        elif expr.value_type == "boolean":
            return "true" if expr.value else "false"
        return str(expr.value)
    elif isinstance(expr, IRAccess):
        root = _expr_to_text(expr.root)
        path = ".".join(
            p if isinstance(p, str) else _expr_to_text(p)
            for p in expr.path
        )
        if path:
            return f"{root}.{path}"
        return root
    elif isinstance(expr, IRCallExpr):
        args_text = ", ".join(_expr_to_text(a) for a in expr.args)
        # Handle unary operators
        if expr.target.startswith("unary_") and len(expr.args) == 1:
            op = expr.target[6:]  # strip "unary_"
            return f"{op}{_expr_to_text(expr.args[0])}"
        if expr.receiver:
            receiver_text = _expr_to_text(expr.receiver)
            return f"{receiver_text}.{expr.target}({args_text})"
        return f"{expr.target}({args_text})"
    return str(expr)


def _collect_accesses(expr, accesses: list, line: int = 0):
    """Recursively find IRAccess nodes and add to flat list."""
    if isinstance(expr, IRAccess):
        accesses.append({"full_text": _expr_to_text(expr), "line": line})
        _collect_accesses(expr.root, accesses, line)
    elif isinstance(expr, IRCallExpr):
        for arg in expr.args:
            _collect_accesses(arg, accesses, line)
        if expr.receiver:
            _collect_accesses(expr.receiver, accesses, line)


def _collect_expr_calls(expr, calls: list, line: int):
    """Recursively find IRCallExpr inside expressions and add as calls."""
    if isinstance(expr, IRCallExpr):
        args_text = ", ".join(_expr_to_text(a) for a in expr.args)
        if expr.receiver:
            receiver_text = _expr_to_text(expr.receiver)
            calls.append({"text": f"{receiver_text}.{expr.target}({args_text})", "line": line})
        else:
            calls.append({"text": f"{expr.target}({args_text})", "line": line})
        for arg in expr.args:
            _collect_expr_calls(arg, calls, line)
        if expr.receiver:
            _collect_expr_calls(expr.receiver, calls, line)
