"""
JS/TS extractor using Tree-sitter.

Walks the Tree-sitter CST and emits a normalized IRModule with:
  - IRFunction for each top-level function/method
  - IRCall, IRAssign, IRBranch, IRReturn for body statements
  - IRVar, IRAccess, IRLiteral, IRCallExpr for expressions
  - Provenance edges for assignment data flow
  - Semantic tags for HTTP_BODY, SHELL_EXEC, etc.
"""

import os
from typing import Optional

from ir import (
    IRModule, IRFunction, IRCall, IRVar, IRAccess, IRLiteral,
    IRAssign, IRBranch, IRReturn, IRCallExpr,
)

try:
    from tree_sitter import Node as TSNode
except ImportError:
    TSNode = None


# ── Sink/source patterns ───────────────────────────────────────────────────

SINK_PATTERNS = {
    "exec", "spawn", "popen", "system", "fork", "execSync", "execFile",
    "prisma.*", "query", "findUnique", "findMany", "create", "update", "delete", "upsert",
    "$executeRawUnsafe", "$transaction", "createMany", "updateMany",
    "writeFile", "writeFileSync", "readFile", "unlink", "appendFile",
    "fetch", "axios.*", "http.request", "https.request", "got.*",
}

SOURCE_ROOTS = {"req", "request", "event", "ctx", "payload", "input", "body"}

# Convention-based heuristics: detect operations by method/function shape, not by exhaustive lists.
# These patterns describe what the code DOES, not whether it's safe.
# The LLM decides security impact. These just surface semantics.
# Conventions used:
#   - Methods named "to*" (toString, toLowerCase) are type coercions
#   - Functions named "parse*", "Number"/"String" are explicit type conversions
#   - Methods like "test", "match" are regex/pattern checks
#   - Functions with "auth"/"verify"/"token"/"session" in name are auth gates

SEP = os.sep


class JsTsExtractor:
    """Extract IR from JS/TS source using Tree-sitter."""

    def __init__(self):
        self._parser = None
        self._init_parser()

    def _init_parser(self):
        if self._parser:
            return
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_javascript as tsjs
            import tree_sitter_typescript as tsts

            self._js_lang = Language(tsjs.language())
            self._ts_lang = Language(tsts.language_typescript())
            self._tsx_lang = Language(tsts.language_tsx())
            self._js_parser = Parser(self._js_lang)
            self._ts_parser = Parser(self._ts_lang)
            self._tsx_parser = Parser(self._tsx_lang)
        except ImportError:
            pass

    def extract(self, source: str, file_path: str, language: str) -> Optional[IRModule]:
        if not self._js_parser:
            return None

        parser = self._js_parser
        if language in ("TypeScript",):
            parser = self._ts_parser
        elif language in ("TSX",):
            parser = self._tsx_parser

        source_bytes = source.encode("utf-8")
        tree = parser.parse(source_bytes)
        root = tree.root_node

        mod = IRModule(file_path=file_path, language=language, functions=[])

        for child in root.named_children:
            fn = self._extract_root_fn(child, source_bytes, file_path)
            if fn:
                mod.functions.append(fn)

        # Post-processing passes
        self._build_provenance(mod)
        self._tag_sources_and_sinks(mod)

        return mod

    # ── Root-level dispatch ────────────────────────────────────────────────

    def _extract_root_fn(self, node, source_bytes, file_path):
        """Extract a function from a root-level node, unwrapping exports."""
        t = node.type

        # export function / export default function / export async function
        if t == "export_statement":
            for child in node.named_children:
                result = self._extract_root_fn(child, source_bytes, file_path)
                if result:
                    return result
            return None

        # export default class { method() {} }
        if t == "lexical_declaration" or t == "variable_declaration":
            stmts = self._extract_lexical_declaration(node, source_bytes, file_path)
            for s in stmts:
                if isinstance(s, IRFunction):
                    return s
            return None

        if t == "expression_statement":
            expr = node.named_children[0] if node.named_children else None
            if expr and expr.type == "arrow_function":
                return self._extract_function(expr, source_bytes, file_path, is_arrow=True)
            return None

        if t in ("function_declaration", "function", "method_definition"):
            return self._extract_function(node, source_bytes, file_path)

        return None

    # ── Function extraction ────────────────────────────────────────────────

    def _extract_function(self, node, source_bytes, file_path, is_arrow=False) -> Optional[IRFunction]:
        name = "<anonymous>"
        params = []
        body_node = None

        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._node_text(name_node, source_bytes)
            params = self._extract_params(
                node.child_by_field_name("parameters") or node.child_by_field_name("formal_parameters"),
                source_bytes,
            )
            body_node = node.child_by_field_name("body")
        elif node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._node_text(name_node, source_bytes)
            params = self._extract_params(
                node.child_by_field_name("parameters") or node.child_by_field_name("formal_parameters"),
                source_bytes,
            )
            body_node = node.child_by_field_name("body")
        elif node.type == "arrow_function" or node.type == "function":
            params = self._extract_params(
                node.child_by_field_name("parameters") or node.child_by_field_name("formal_parameters"),
                source_bytes,
            )
            body_node = node.child_by_field_name("body")
            # For arrow functions without block body, wrap in return
            if body_node and body_node.type != "statement_block":
                pass  # handled below

        if not body_node:
            return None

        is_async = "async" in self._node_text(node, source_bytes).lower()
        line = node.start_point[0] + 1

        if body_node.type == "statement_block":
            body_stmts = self._extract_block(body_node, source_bytes, file_path)
        elif body_node.type in (
            "call_expression", "member_expression", "identifier",
            "string", "number", "true", "false", "null",
            "binary_expression", "unary_expression", "await",
            "template_string", "array", "object",
        ):
            expr = self._extract_expr(body_node, source_bytes, file_path)
            body_stmts = [IRReturn(value=expr, line=line)]
        else:
            body_stmts = []

        fn = IRFunction(
            name=name,
            params=params,
            body=body_stmts,
            file_path=file_path,
            line=line,
            is_async=is_async,
        )

        return fn

    # ── Statement extraction ───────────────────────────────────────────────

    def _extract_block(self, node, source_bytes, file_path) -> list:
        stmts = []
        for child in node.named_children:
            stmt = self._extract_stmt(child, source_bytes, file_path)
            if isinstance(stmt, list):
                stmts.extend(stmt)
            elif stmt is not None:
                stmts.append(stmt)
        return stmts

    def _extract_stmt(self, node, source_bytes, file_path):
        t = node.type

        if t == "expression_statement":
            inner = node.named_children[0] if node.named_children else None
            if inner:
                if inner.type == "call_expression":
                    return self._extract_call_stmt(inner, source_bytes, file_path)
                elif inner.type == "assignment_expression":
                    return self._extract_assign_expr(inner, source_bytes, file_path)
                elif inner.type == "member_expression":
                    return self._extract_call_stmt(inner, source_bytes, file_path)
                elif inner.type == "arrow_function":
                    fn = self._extract_function(inner, source_bytes, file_path, is_arrow=True)
                    return fn if fn else None
                else:
                    return None

        elif t == "return_statement":
            val_node = node.child_by_field_name("value")
            if not val_node:
                # Some grammars (JS/TS) don't expose a "value" field; use first named child
                named = node.named_children
                val_node = named[0] if named else None
            value = self._extract_expr(val_node, source_bytes, file_path) if val_node else None
            return IRReturn(value=value, line=node.start_point[0] + 1)

        elif t == "lexical_declaration" or t == "variable_declaration":
            return self._extract_lexical_declaration(node, source_bytes, file_path)

        elif t == "if_statement":
            cond_node = node.child_by_field_name("condition")
            cons_node = node.child_by_field_name("consequence")
            alt_node = node.child_by_field_name("alternative")

            condition = self._extract_expr(cond_node, source_bytes, file_path) if cond_node else IRLiteral(True, "boolean")
            if condition is None:
                condition = IRLiteral(True, "boolean")

            true_body = self._extract_block(cons_node, source_bytes, file_path) if cons_node else []
            false_body = self._extract_block(alt_node, source_bytes, file_path) if alt_node else []

            return IRBranch(
                condition=condition,
                true_body=true_body,
                false_body=false_body,
                line=node.start_point[0] + 1,
            )

        elif t == "try_statement":
            stmts = []
            body_node = node.child_by_field_name("body")
            if body_node:
                stmts.extend(self._extract_block(body_node, source_bytes, file_path))
            catch_node = node.child_by_field_name("handler")
            if catch_node:
                catch_body = catch_node.child_by_field_name("body")
                if catch_body:
                    stmts.extend(self._extract_block(catch_body, source_bytes, file_path))
            finally_node = node.child_by_field_name("finally")
            if finally_node:
                fb = finally_node.child_by_field_name("body")
                if fb:
                    stmts.extend(self._extract_block(fb, source_bytes, file_path))
            return stmts

        elif t == "throw_statement":
            val_node = node.child_by_field_name("value")
            _ = self._extract_expr(val_node, source_bytes, file_path) if val_node else None
            return None  # throw is control flow, not data flow

        elif t in ("for_statement", "for_in_statement", "for_of_statement"):
            body_node = node.child_by_field_name("body")
            return self._extract_block(body_node, source_bytes, file_path) if body_node else []

        elif t in ("while_statement", "do_statement"):
            body_node = node.child_by_field_name("body")
            return self._extract_block(body_node, source_bytes, file_path) if body_node else []

        elif t in ("function_declaration", "method_definition", "arrow_function", "function"):
            return self._extract_function(node, source_bytes, file_path)

        elif t in ("switch_statement", "switch_case"):
            return []  # skip switch for now

        return None

    def _extract_call_stmt(self, node, source_bytes, file_path) -> Optional[IRCall]:
        line = node.start_point[0] + 1
        receiver = None
        target = ""

        fn_node = node.child_by_field_name("function") if node.type == "call_expression" else node
        if not fn_node and node.named_children:
            fn_node = node.named_children[0]

        if not fn_node:
            return None

        if fn_node.type == "member_expression":
            receiver = self._extract_expr(self._get_object(fn_node), source_bytes, file_path)
            target = self._node_text(self._get_property(fn_node), source_bytes)
        elif fn_node.type == "identifier":
            target = self._node_text(fn_node, source_bytes)
        else:
            target = self._node_text(fn_node, source_bytes)

        args_node = node.child_by_field_name("arguments") if node.type == "call_expression" else None
        args = []
        if args_node:
            for arg in args_node.named_children:
                expr = self._extract_expr(arg, source_bytes, file_path)
                if expr is not None:
                    args.append(expr)

        return IRCall(target=target, args=args, receiver=receiver, line=line)

    # ── Expression extraction ──────────────────────────────────────────────

    def _extract_expr(self, node, source_bytes, file_path) -> Optional[object]:
        if node is None:
            return None
        t = node.type

        if t == "identifier":
            name = self._node_text(node, source_bytes)
            return IRVar(name=name)

        elif t == "member_expression":
            return self._extract_member_expr(node, source_bytes, file_path)

        elif t == "call_expression":
            return self._extract_call_expr(node, source_bytes, file_path)

        elif t == "string":
            raw = self._node_text(node, source_bytes)
            val = raw.strip("'\"`")
            return IRLiteral(val, "string")

        elif t == "number":
            raw = self._node_text(node, source_bytes)
            try:
                val = int(raw) if "." not in raw else float(raw)
            except (ValueError, TypeError):
                val = 0
            vtype = "number"
            return IRLiteral(val, vtype)

        elif t == "true":
            return IRLiteral(True, "boolean")

        elif t == "false":
            return IRLiteral(False, "boolean")

        elif t == "null":
            return IRLiteral(None, "null")

        elif t == "unary_expression":
            op = self._node_text(node.child_by_field_name("operator"), source_bytes)
            arg = self._extract_expr(node.child_by_field_name("argument"), source_bytes, file_path)
            if arg:
                return IRCallExpr(target=f"unary_{op}", args=[arg])
            return None

        elif t == "binary_expression":
            op = self._node_text(node.child_by_field_name("operator"), source_bytes)
            left = self._extract_expr(node.child_by_field_name("left"), source_bytes, file_path)
            right = self._extract_expr(node.child_by_field_name("right"), source_bytes, file_path)
            args = [a for a in [left, right] if a is not None]
            if args:
                return IRCallExpr(target=f"bin_{op}", args=args)
            return None

        elif t == "parenthesized_expression":
            if node.named_children:
                return self._extract_expr(node.named_children[0], source_bytes, file_path)
            return None

        elif t == "await_expression":
            arg = self._extract_expr(node.named_children[0], source_bytes, file_path) if node.named_children else None
            return arg

        elif t == "template_string":
            return IRLiteral(self._node_text(node, source_bytes)[:80], "string")

        elif t == "assignment_expression":
            return self._extract_assign_expr(node, source_bytes, file_path)

        return None

    def _extract_member_expr(self, node, source_bytes, file_path) -> IRAccess:
        obj_node = self._get_object(node)
        prop_node = self._get_property(node)

        if obj_node is None or prop_node is None:
            return IRVar(name=self._node_text(node, source_bytes))

        root = self._extract_expr(obj_node, source_bytes, file_path)
        if root is None:
            root = IRVar(name="<unknown>")

        path = []

        # If the object is itself a member_expression, flatten it
        if isinstance(root, IRAccess):
            path = root.path[:]
            root = root.root

        prop_text = self._node_text(prop_node, source_bytes)
        path.append(prop_text)

        return IRAccess(root=root, path=path)

    def _extract_idents_from_node(self, node, source_bytes) -> list[IRVar]:
        """Walk a Tree-sitter CST subtree and collect identifier-type nodes as IRVars."""
        vars = []
        if node.type == "identifier" or node.type == "shorthand_property_identifier":
            name = self._node_text(node, source_bytes)
            vars.append(IRVar(name=name))
        else:
            for child in node.named_children:
                vars.extend(self._extract_idents_from_node(child, source_bytes))
        return vars

    def _extract_call_expr(self, node, source_bytes, file_path) -> Optional[IRCallExpr]:
        fn_node = node.child_by_field_name("function")
        if not fn_node and node.named_children:
            fn_node = node.named_children[0]
        if not fn_node:
            return None

        args_node = node.child_by_field_name("arguments")
        args = []
        if args_node:
            for arg in args_node.named_children:
                expr = self._extract_expr(arg, source_bytes, file_path)
                if expr is not None:
                    args.append(expr)
                else:
                    idents = self._extract_idents_from_node(arg, source_bytes)
                    args.extend(idents)

        if fn_node.type == "member_expression":
            receiver = self._extract_expr(self._get_object(fn_node), source_bytes, file_path)
            target = self._node_text(self._get_property(fn_node), source_bytes)
            return IRCallExpr(target=target, args=args, receiver=receiver)
        else:
            target = self._node_text(fn_node, source_bytes)
            return IRCallExpr(target=target, args=args)

    def _extract_assign_expr(self, node, source_bytes, file_path) -> Optional[IRAssign]:
        target_node = node.child_by_field_name("left") or node.child_by_field_name("name") or node.child_by_field_name("pattern")
        value_node = node.child_by_field_name("right") or node.child_by_field_name("value") or node.child_by_field_name("init")

        # Handle variable_declarator nodes inside lexical_declaration
        if node.type == "variable_declarator":
            target_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")

        if not target_node:
            return None

        target = self._node_text(target_node, source_bytes)
        if not value_node:
            return None

        value = self._extract_expr(value_node, source_bytes, file_path)
        if value is None:
            return None

        return IRAssign(target=target, value=value, line=node.start_point[0] + 1)

    def _extract_lexical_declaration(self, node, source_bytes, file_path) -> list:
        stmts = []
        for child in node.named_children:
            if child.type == "variable_declarator":
                assign = self._extract_assign_expr(child, source_bytes, file_path)
                if assign:
                    stmts.append(assign)
            elif child.type in ("function_declaration", "arrow_function", "function"):
                fn = self._extract_function(child, source_bytes, file_path)
                if fn:
                    stmts.append(fn)
        return stmts

    # ── Provenance edge building ───────────────────────────────────────────

    def _build_provenance(self, mod: IRModule):
        """Walk all functions in a module and add provenance edges."""
        for fn in mod.functions:
            self._build_fn_provenance(fn, mod)

    def _build_fn_provenance(self, fn: IRFunction, mod: IRModule):
        for stmt in fn.body:
            self._build_stmt_provenance(stmt, mod, [])

    def _build_stmt_provenance(self, stmt, mod: IRModule, conditions: list[int]):
        if isinstance(stmt, IRAssign):
            if stmt.value:
                # Edges from all expression nodes (including IRAccess) to the assignment
                all_expr_ids = self._collect_all_expr_ids(stmt.value)
                for eid in all_expr_ids:
                    mod.add_edge(
                        source_id=eid,
                        target_id=stmt.id,
                        transform="assign",
                        conditions=conditions or None,
                    )
                # Edge from assignment statement to the target variable(s) or property access
                destructured_vars = self._parse_destructured_vars(stmt.target)
                if destructured_vars:
                    for var_name in destructured_vars:
                        var_id = IRVar(var_name).id
                        mod.add_edge(
                            source_id=stmt.id,
                            target_id=var_id,
                            transform="assign_target",
                            conditions=conditions or None,
                        )
                else:
                    if "." in stmt.target:
                        parts = stmt.target.split(".")
                        root_name = parts[0]
                        prop_path = parts[1:]
                        access_id = IRAccess(root=IRVar(root_name), path=prop_path).id
                        root_id = IRVar(root_name).id
                        mod.add_edge(
                            source_id=stmt.id,
                            target_id=access_id,
                            transform="assign_target",
                            conditions=conditions or None,
                        )
                        mod.add_edge(
                            source_id=stmt.id,
                            target_id=root_id,
                            transform="assign_target_root",
                            conditions=conditions or None,
                        )
                    else:
                        target_var_id = IRVar(stmt.target).id
                        mod.add_edge(
                            source_id=stmt.id,
                            target_id=target_var_id,
                            transform="assign_target",
                            conditions=conditions or None,
                        )
                # Also track variable-to-variable edges for later resolution
                self._build_expr_provenance(stmt.value, mod, conditions)

        elif isinstance(stmt, IRCall):
            # Edge from each arg to the call (for sink detection)
            for arg in stmt.args:
                src_ids = self._collect_var_ids(arg)
                for sid in src_ids:
                    mod.add_edge(
                        source_id=sid,
                        target_id=stmt.id,
                        transform=stmt.target,
                        conditions=conditions or None,
                    )
            # If call has a result_var, edge from call to result
            if stmt.result_var:
                assign_id = f"assign_{stmt.result_var}"  # synthetic ID for the assignment
                mod.add_edge(
                    source_id=stmt.id,
                    target_id=assign_id,  # will be resolved to actual node later
                    transform=stmt.target,
                    conditions=conditions or None,
                )

        elif isinstance(stmt, IRBranch):
            branch_conds = conditions + [stmt.line]
            for s in stmt.true_body:
                self._build_stmt_provenance(s, mod, branch_conds)
            for s in stmt.false_body:
                self._build_stmt_provenance(s, mod, branch_conds)

        elif isinstance(stmt, IRReturn):
            if stmt.value:
                src_ids = self._collect_var_ids(stmt.value)
                for sid in src_ids:
                    mod.add_edge(
                        source_id=sid,
                        target_id=stmt.id,
                        transform="return",
                        conditions=conditions or None,
                    )

    def _build_expr_provenance(self, expr, mod: IRModule, conditions: list[int]):
        """Recurse into expressions to find nested calls with result vars."""
        if isinstance(expr, IRCallExpr):
            assign_id = f"assign_expr_{expr.id}"
            mod.add_edge(
                source_id=expr.id,
                target_id=assign_id,
                transform=expr.target,
                conditions=conditions or None,
            )
            for arg in expr.args:
                self._build_expr_provenance(arg, mod, conditions)

    def _collect_var_ids(self, expr) -> list[str]:
        """Collect all IRVar IDs referenced in an expression."""
        ids = []
        if isinstance(expr, IRVar):
            ids.append(expr.id)
        elif isinstance(expr, IRAccess):
            ids.extend(self._collect_var_ids(expr.root))
            for p in expr.path:
                if isinstance(p, IRAccess):
                    ids.extend(self._collect_var_ids(p))
        elif isinstance(expr, IRCallExpr):
            for arg in expr.args:
                ids.extend(self._collect_var_ids(arg))
            if expr.receiver:
                ids.extend(self._collect_var_ids(expr.receiver))
        return ids

    @staticmethod
    def _parse_destructured_vars(target: str) -> list[str]:
        """Extract variable names from a destructuring target like '{ a, b: c, ...rest }' or '[a, b]'."""
        text = target.strip()
        if text.startswith("{"):
            inner = text[1:]
            if inner.endswith("}"):
                inner = inner[:-1]
        elif text.startswith("["):
            inner = text[1:]
            if inner.endswith("]"):
                inner = inner[:-1]
        else:
            return []
        names = []
        depth = 0
        buf = ""
        for ch in inner:
            if ch in "{[(":
                depth += 1
                buf += ch
            elif ch in "}])":
                depth -= 1
                buf += ch
            elif ch == "," and depth == 0:
                names.append(buf.strip())
                buf = ""
            else:
                buf += ch
        remaining = buf.strip()
        if remaining:
            names.append(remaining)
        result = []
        for part in names:
            if part.startswith("..."):
                continue
            if ":" in part and not part.startswith("{"):
                alias = part.split(":", 1)[1].strip()
                if alias and not alias.startswith("{"):
                    result.append(alias)
                    continue
            if part and not part.startswith(("{", "[")):
                result.append(part)
        return result

    def _collect_all_expr_ids(self, expr) -> list[str]:
        """Collect all expression node IDs from an expression tree."""
        ids = []
        if isinstance(expr, IRVar):
            ids.append(expr.id)
        elif isinstance(expr, IRAccess):
            ids.append(expr.id)
            ids.extend(self._collect_all_expr_ids(expr.root))
            for p in expr.path:
                if isinstance(p, IRAccess):
                    ids.extend(self._collect_all_expr_ids(p))
        elif isinstance(expr, IRCallExpr):
            ids.append(expr.id)
            for arg in expr.args:
                ids.extend(self._collect_all_expr_ids(arg))
            if expr.receiver:
                ids.extend(self._collect_all_expr_ids(expr.receiver))
        elif isinstance(expr, IRLiteral):
            ids.append(expr.id)
        return ids

    # ── Semantic tagging ───────────────────────────────────────────────────

    def _tag_sources_and_sinks(self, mod: IRModule):
        """Pattern-match IR nodes to assign semantic tags."""
        for fn in mod.functions:
            for stmt in fn.body:
                self._tag_stmt(mod, stmt)

    def _tag_stmt(self, mod: IRModule, stmt):
        if isinstance(stmt, IRAssign):
            self._tag_expr(mod, stmt.value)
        elif isinstance(stmt, IRCall):
            self._tag_call(mod, stmt)
        elif isinstance(stmt, IRBranch):
            self._tag_stmt(mod, stmt.condition)
            for s in stmt.true_body:
                self._tag_stmt(mod, s)
            for s in stmt.false_body:
                self._tag_stmt(mod, s)

    def _tag_call(self, mod: IRModule, call: IRCall):
        target = call.target.lower()
        for pat in SINK_PATTERNS:
            if pat.endswith(".*"):
                prefix = pat[:-2]
                if target.startswith(prefix):
                    mod.add_tag(f"SINK_{pat.replace('.*', '').upper()}", call.id)
                    break
            elif target == pat:
                mod.add_tag(f"SINK_{pat.upper()}", call.id)
                break
        # Tag auth operations (convention-based: function name suggests auth/identity check)
        if any(kw in target for kw in ("auth", "verify", "authorize", "login", "authenticate")) or \
           target.startswith("get") and any(kw in target for kw in ("token", "session", "user")):
            mod.add_tag("OP_AUTH", call.id)
        # Tag HTTP sources on calls like req.body, req.json()
        if target in ("json", "body", "text", "formData"):
            if call.receiver:
                if isinstance(call.receiver, IRVar) and call.receiver.name in SOURCE_ROOTS:
                    mod.add_tag("SOURCE_HTTP_BODY", call.id)
                elif isinstance(call.receiver, IRAccess):
                    if isinstance(call.receiver.root, IRVar):
                        tag = self._source_tag_for_access(call.receiver.root.name, call.receiver.path)
                        if tag:
                            mod.add_tag(tag, call.id)

    def _source_tag_for_access(self, root_name: str, path: list) -> str | None:
        """Determine source tag based on full access chain."""
        if root_name in SOURCE_ROOTS:
            if path and isinstance(path[0], str):
                first = path[0].lower()
                if first in ("body",):
                    return "SOURCE_HTTP_BODY"
                elif first in ("params",):
                    return "SOURCE_URL_PARAM"
                elif first in ("query",):
                    return "SOURCE_URL_QUERY"
                elif first in ("json",):
                    return "SOURCE_HTTP_BODY"
            return "SOURCE_HTTP_BODY"
        if root_name == "session":
            return "SOURCE_SESSION"
        if root_name == "process" and path and path[0] == "env":
            return "SOURCE_ENV"
        return None

    def _tag_operations(self, mod: IRModule, expr: IRCallExpr):
        """Tag semantic operations on call expressions using convention-based heuristics."""
        target = expr.target.lower()

        # Coercion: methods starting with "to" (toString, toLowerCase) or named "trim"
        if target.startswith("to") and len(target) > 2:
            mod.add_tag("OP_COERCION", expr.id)
            mod.add_tag("VALIDATION_GATE", expr.id)
        elif target in ("trim", "trimstart", "trimend"):
            mod.add_tag("OP_COERCION", expr.id)
            mod.add_tag("VALIDATION_GATE", expr.id)
        # Coercion: standalone type-coercion functions
        elif target in ("number", "string", "boolean", "bigint") or target.startswith("parse"):
            mod.add_tag("OP_COERCION", expr.id)
            mod.add_tag("VALIDATION_GATE", expr.id)
        # Validation: regex/pattern checks
        elif target in ("test", "match", "exec"):
            if expr.args:
                mod.add_tag("OP_VALIDATION", expr.id)
                mod.add_tag("VALIDATION_GATE", expr.id)
        # Validation: schema validation (parse/safeParse/validate)
        elif target in ("validate",) or target.endswith("parse") or target.endswith("schemacheck"):
            mod.add_tag("OP_VALIDATION", expr.id)
            mod.add_tag("VALIDATION_GATE", expr.id)

    def _tag_expr(self, mod: IRModule, expr):
        if isinstance(expr, IRAccess):
            if isinstance(expr.root, IRVar):
                tag = self._source_tag_for_access(expr.root.name, expr.path)
                if tag:
                    mod.add_tag(tag, expr.id)
        elif isinstance(expr, IRCallExpr):
            target = expr.target.lower()
            # Tag HTTP sources on call patterns like req.json(), req.text(), etc.
            if target in ("json", "body", "text", "formData"):
                if isinstance(expr.receiver, IRVar) and expr.receiver.name in SOURCE_ROOTS:
                    mod.add_tag("SOURCE_HTTP_BODY", expr.id)
                elif isinstance(expr.receiver, IRAccess):
                    if isinstance(expr.receiver.root, IRVar):
                        tag = self._source_tag_for_access(expr.receiver.root.name, expr.receiver.path)
                        if tag:
                            mod.add_tag(tag, expr.id)
            # Tag operations
            self._tag_operations(mod, expr)
            # Tag sinks
            for pat in SINK_PATTERNS:
                if pat.endswith(".*"):
                    prefix = pat[:-2]
                    if target.startswith(prefix):
                        mod.add_tag(f"SINK_{pat.replace('.*', '').upper()}", expr.id)
                        break
                elif target == pat:
                    mod.add_tag(f"SINK_{pat.upper()}", expr.id)
                    break
            for arg in expr.args:
                self._tag_expr(mod, arg)
            if expr.receiver:
                self._tag_expr(mod, expr.receiver)

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _node_text(node, source_bytes) -> str:
        try:
            return node.text.decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _get_object(node):
        return node.child_by_field_name("object")

    @staticmethod
    def _get_property(node):
        return node.child_by_field_name("property")

    @staticmethod
    def _extract_params(node, source_bytes) -> list[str]:
        if not node:
            return []
        return [
            JsTsExtractor._node_text(p, source_bytes)
            for p in node.named_children
        ]

    @staticmethod
    def _is_negation(cond_node, source_bytes) -> bool:
        if cond_node is None:
            return False
        # Check for `!` prefix
        if cond_node.type == "parenthesized_expression" and cond_node.named_children:
            cond_node = cond_node.named_children[0]
        return cond_node.type == "unary_expression" and JsTsExtractor._node_text(
            cond_node.child_by_field_name("operator"), source_bytes
        ) == "!"

    @staticmethod
    def _strip_negation(condition, cond_node, source_bytes) -> object:
        """Return the inner expression after removing negation."""
        if cond_node.type == "parenthesized_expression" and cond_node.named_children:
            cond_node = cond_node.named_children[0]
        if cond_node.type == "unary_expression":
            arg_node = cond_node.child_by_field_name("argument")
            if arg_node:
                return condition.args[0] if isinstance(condition, IRCallExpr) and condition.target == "unary_!" else condition
        return condition
