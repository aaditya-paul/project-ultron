import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ir import (
    IRModule, IRFunction, IRCall, IRVar, IRAccess, IRLiteral,
    IRAssign, IRBranch, IRReturn, IRCallExpr, Edge, Tag, CallResolution,
)


class TestIRConstruction(unittest.TestCase):

    def test_irvar_default_id(self):
        v = IRVar("x")
        self.assertTrue(v.id.startswith("VAR_"))
        self.assertEqual(len(v.id), 11)  # "VAR_" + 7 hex chars
        self.assertEqual(v.type, "IRVar")

    def test_irvar_stable_id(self):
        self.assertEqual(IRVar("x").id, IRVar("x").id)

    def test_irvar_different_names_different_ids(self):
        self.assertNotEqual(IRVar("x").id, IRVar("y").id)

    def test_irvar_custom_id(self):
        v = IRVar("x", id="my_custom_id")
        self.assertEqual(v.id, "my_custom_id")

    def test_irliteral(self):
        lit = IRLiteral(42, "number")
        self.assertEqual(lit.value, 42)
        self.assertEqual(lit.value_type, "number")
        self.assertTrue(lit.id.startswith("LIT_"))

    def test_irliteral_none(self):
        lit = IRLiteral(None, "null")
        self.assertIsNone(lit.value)
        self.assertTrue(lit.id.startswith("LIT_"))

    def test_iraccess_simple(self):
        acc = IRAccess(root=IRVar("req"), path=["body"])
        self.assertEqual(acc.path, ["body"])
        self.assertIsInstance(acc.root, IRVar)
        self.assertEqual(acc.root.name, "req")
        self.assertTrue(acc.id.startswith("ACCESS_"))

    def test_iraccess_chained(self):
        acc = IRAccess(root=IRVar("req"), path=["body", "user", "email"])
        self.assertEqual(acc.path, ["body", "user", "email"])
        self.assertTrue(acc.id.startswith("ACCESS_"))

    def test_ircallexpr(self):
        ce = IRCallExpr(target="sanitize", args=[IRVar("x")])
        self.assertEqual(ce.target, "sanitize")
        self.assertEqual(len(ce.args), 1)
        self.assertTrue(ce.id.startswith("CALLE_"))

    def test_ircallexpr_with_receiver(self):
        ce = IRCallExpr(target="findUnique", args=[IRVar("id")], receiver=IRAccess(root=IRVar("prisma"), path=["user"]))
        self.assertIsNotNone(ce.receiver)
        self.assertTrue(ce.id.startswith("CALLE_"))


class TestIRStmt(unittest.TestCase):

    def test_ircall(self):
        c = IRCall(target="exec", args=[IRVar("cmd")])
        self.assertEqual(c.target, "exec")
        self.assertEqual(len(c.args), 1)
        self.assertTrue(c.id.startswith("CALL_"))

    def test_ircall_with_result(self):
        c = IRCall(target="prisma.user.findUnique", args=[IRVar("id")], result_var="user")
        self.assertEqual(c.result_var, "user")

    def test_ircall_with_receiver(self):
        c = IRCall(target="findUnique", args=[IRVar("id")], receiver=IRAccess(root=IRVar("prisma"), path=["user"]))
        self.assertIsNotNone(c.receiver)

    def test_irassign(self):
        a = IRAssign(target="x", value=IRVar("y"))
        self.assertEqual(a.target, "x")
        self.assertIsInstance(a.value, IRVar)
        self.assertTrue(a.id.startswith("ASSIGN_"))

    def test_irassign_with_access(self):
        a = IRAssign(target="id", value=IRAccess(root=IRVar("req"), path=["body", "id"]))
        self.assertIsInstance(a.value, IRAccess)
        self.assertEqual(a.value.path, ["body", "id"])

    def test_irbranch_simple(self):
        b = IRBranch(
            condition=IRCallExpr(target="isValid", args=[IRVar("x")]),
            true_body=[IRCall(target="exec", args=[IRVar("x")])],
            false_body=[],
        )
        self.assertIsInstance(b.condition, IRCallExpr)
        self.assertEqual(len(b.true_body), 1)
        self.assertEqual(len(b.false_body), 0)
        self.assertTrue(b.id.startswith("BRANCH_"))

    def test_irbranch_with_else(self):
        b = IRBranch(
            condition=IRVar("admin"),
            true_body=[IRCall(target="exec", args=[IRVar("cmd")])],
            false_body=[IRCall(target="logger.warn", args=[IRVar("cmd")])],
        )
        self.assertEqual(len(b.true_body), 1)
        self.assertEqual(len(b.false_body), 1)

    def test_irreturn_none(self):
        r = IRReturn()
        self.assertIsNone(r.value)

    def test_irreturn_with_value(self):
        r = IRReturn(value=IRAccess(root=IRVar("req"), path=["body"]))
        self.assertIsNotNone(r.value)
        self.assertIsInstance(r.value, IRAccess)


class TestIRFunction(unittest.TestCase):

    def test_function_basic(self):
        fn = IRFunction(
            name="handler",
            params=["req", "res"],
            file_path="src/api/test.ts",
            body=[],
        )
        self.assertEqual(fn.name, "handler")
        self.assertEqual(fn.params, ["req", "res"])
        self.assertEqual(fn.file_path, "src/api/test.ts")
        self.assertTrue(fn.id.startswith("FUNC_"))

    def test_function_with_body(self):
        fn = IRFunction(
            name="getUser",
            params=["id"],
            file_path="src/api/users.ts",
            body=[
                IRAssign(target="user", value=IRCallExpr(target="db.query", args=[IRVar("id")])),
                IRReturn(value=IRVar("user")),
            ],
        )
        self.assertEqual(len(fn.body), 2)
        self.assertIsInstance(fn.body[0], IRAssign)
        self.assertIsInstance(fn.body[1], IRReturn)

    def test_function_async(self):
        fn = IRFunction(
            name="fetchData",
            params=[],
            file_path="src/api/data.ts",
            body=[],
            is_async=True,
        )
        self.assertTrue(fn.is_async)


class TestParallelLayers(unittest.TestCase):

    def test_edge_defaults(self):
        e = Edge(source_id="VAR_abc123", target_id="CALL_def456")
        self.assertEqual(e.source_id, "VAR_abc123")
        self.assertEqual(e.target_id, "CALL_def456")
        self.assertIsNone(e.transform)
        self.assertEqual(e.conditions, [])
        self.assertEqual(e.confidence, 1.0)

    def test_edge_full(self):
        e = Edge(
            source_id="VAR_abc123",
            target_id="CALL_def456",
            transform="sanitize",
            conditions=[10, 12],
            confidence=0.85,
        )
        self.assertEqual(e.transform, "sanitize")
        self.assertEqual(e.conditions, [10, 12])
        self.assertEqual(e.confidence, 0.85)

    def test_tag(self):
        t = Tag(kind="HTTP_BODY", node_id="ACCESS_abc123")
        self.assertEqual(t.kind, "HTTP_BODY")
        self.assertEqual(t.node_id, "ACCESS_abc123")


class TestIRModule(unittest.TestCase):

    def setUp(self):
        self.fn = IRFunction(
            name="getUser",
            params=["req", "res"],
            file_path="src/api/users.ts",
            body=[
                IRAssign(target="id", value=IRAccess(root=IRVar("req"), path=["body", "id"]), line=3),
                IRCall(target="db.query", args=[IRVar("id")], result_var="user", line=5),
                IRCall(target="res.json", args=[IRVar("user")], line=7),
            ],
        )
        self.mod = IRModule(
            file_path="src/api/users.ts",
            language="TypeScript",
            functions=[self.fn],
        )

    def test_module_properties(self):
        self.assertEqual(self.mod.file_path, "src/api/users.ts")
        self.assertEqual(self.mod.language, "TypeScript")
        self.assertEqual(len(self.mod.functions), 1)
        self.assertEqual(len(self.mod.provenance_edges), 0)
        self.assertEqual(len(self.mod.semantic_tags), 0)

    def test_add_edge(self):
        self.mod.add_edge(
            source_id=self.fn.body[0].value.id,
            target_id=self.fn.body[0].id,
            transform="assign",
        )
        self.assertEqual(len(self.mod.provenance_edges), 1)
        e = self.mod.provenance_edges[0]
        self.assertEqual(e.source_id, self.fn.body[0].value.id)
        self.assertEqual(e.target_id, self.fn.body[0].id)

    def test_add_tag(self):
        self.mod.add_tag("HTTP_BODY", self.fn.body[0].value.id)
        self.assertEqual(len(self.mod.semantic_tags), 1)
        t = self.mod.semantic_tags[0]
        self.assertEqual(t.kind, "HTTP_BODY")

    def test_get_function_found(self):
        result = self.mod.get_function(self.fn.id)
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "getUser")

    def test_get_function_not_found(self):
        result = self.mod.get_function("NONEXISTENT")
        self.assertIsNone(result)

    def test_collect_nodes(self):
        nodes = self.mod.collect_nodes()
        self.assertEqual(len(nodes), 4)  # 1 function + 3 statements


class TestIRSerialization(unittest.TestCase):

    def setUp(self):
        self.fn = IRFunction(
            name="getUser",
            params=["req"],
            file_path="src/api/users.ts",
            body=[
                IRAssign(target="id", value=IRAccess(root=IRVar("req"), path=["body", "id"]), line=3),
                IRBranch(
                    condition=IRCallExpr(target="isValid", args=[IRVar("id")]),
                    true_body=[IRCall(target="db.query", args=[IRVar("id")], line=5)],
                    false_body=[IRCall(target="res.status", args=[IRLiteral(400, "number")], line=7)],
                ),
            ],
        )
        self.mod = IRModule(
            file_path="src/api/users.ts",
            language="TypeScript",
            functions=[self.fn],
        )
        self.mod.add_edge(source_id="VAR_test", target_id="CALL_test", transform="assign")
        self.mod.add_tag("HTTP_BODY", "ACCESS_test")

    def test_to_json_round_trip(self):
        j = self.mod.to_json()
        mod2 = IRModule.from_json(j)
        self.assertEqual(mod2.file_path, self.mod.file_path)
        self.assertEqual(mod2.language, self.mod.language)
        self.assertEqual(len(mod2.functions), 1)

    def test_round_trip_preserves_body(self):
        mod2 = IRModule.from_json(self.mod.to_json())
        f2 = mod2.functions[0]
        self.assertEqual(f2.name, "getUser")
        self.assertEqual(f2.params, ["req"])
        self.assertEqual(len(f2.body), 2)
        self.assertIsInstance(f2.body[0], IRAssign)
        self.assertIsInstance(f2.body[1], IRBranch)

    def test_round_trip_preserves_branch_structure(self):
        mod2 = IRModule.from_json(self.mod.to_json())
        branch = mod2.functions[0].body[1]
        self.assertEqual(len(branch.true_body), 1)
        self.assertEqual(len(branch.false_body), 1)
        self.assertIsInstance(branch.condition, IRCallExpr)
        self.assertEqual(branch.condition.target, "isValid")

    def test_round_trip_preserves_parallel_layers(self):
        mod2 = IRModule.from_json(self.mod.to_json())
        self.assertEqual(len(mod2.provenance_edges), 1)
        self.assertEqual(len(mod2.semantic_tags), 1)

    def test_round_trip_preserves_ids(self):
        mod2 = IRModule.from_json(self.mod.to_json())
        f1 = self.mod.functions[0]
        f2 = mod2.functions[0]
        self.assertEqual(f1.id, f2.id)
        self.assertEqual(f1.body[0].id, f2.body[0].id)
        self.assertEqual(f1.body[1].id, f2.body[1].id)

    def test_to_json_is_valid(self):
        import json
        j = self.mod.to_json()
        data = json.loads(j)
        self.assertIn("functions", data)
        self.assertIn("provenance_edges", data)
        self.assertIn("semantic_tags", data)
        self.assertIn("file_path", data)
        self.assertIn("language", data)

    def test_empty_module(self):
        mod = IRModule(file_path="empty.ts", language="TypeScript", functions=[])
        j = mod.to_json()
        mod2 = IRModule.from_json(j)
        self.assertEqual(len(mod2.functions), 0)
        self.assertEqual(len(mod2.provenance_edges), 0)
        self.assertEqual(len(mod2.semantic_tags), 0)


class TestEdgeSerialization(unittest.TestCase):

    def test_edge_to_dict_minimal(self):
        e = Edge(source_id="s1", target_id="t1")
        d = e.to_dict()
        self.assertEqual(d["source_id"], "s1")
        self.assertEqual(d["target_id"], "t1")
        self.assertNotIn("transform", d)
        self.assertNotIn("conditions", d)
        self.assertNotIn("confidence", d)

    def test_edge_to_dict_full(self):
        e = Edge(source_id="s1", target_id="t1", transform="sanitize", conditions=[1, 2], confidence=0.75)
        d = e.to_dict()
        self.assertEqual(d["transform"], "sanitize")
        self.assertEqual(d["conditions"], [1, 2])
        self.assertEqual(d["confidence"], 0.75)

    def test_edge_round_trip(self):
        e = Edge(source_id="VAR_abc", target_id="CALL_def", transform="exec", conditions=[42], confidence=0.9)
        e2 = Edge.from_dict(e.to_dict())
        self.assertEqual(e.source_id, e2.source_id)
        self.assertEqual(e.target_id, e2.target_id)
        self.assertEqual(e.transform, e2.transform)
        self.assertEqual(e.conditions, e2.conditions)
        self.assertEqual(e.confidence, e2.confidence)


class TestEdgeCases(unittest.TestCase):

    def test_nested_branch(self):
        fn = IRFunction(
            name="process",
            params=["req"],
            file_path="src/api/data.ts",
            body=[
                IRBranch(
                    condition=IRVar("admin"),
                    true_body=[
                        IRBranch(
                            condition=IRCallExpr(target="isValid", args=[IRAccess(root=IRVar("req"), path=["body"])]),
                            true_body=[IRCall(target="exec", args=[IRAccess(root=IRVar("req"), path=["body", "cmd"])])],
                            false_body=[],
                        ),
                    ],
                    false_body=[IRReturn()],
                ),
            ],
        )
        mod = IRModule(file_path="src/api/data.ts", language="TypeScript", functions=[fn])
        j = mod.to_json()
        mod2 = IRModule.from_json(j)
        outer = mod2.functions[0].body[0]
        self.assertIsInstance(outer, IRBranch)
        inner = outer.true_body[0]
        self.assertIsInstance(inner, IRBranch)
        self.assertEqual(len(inner.true_body), 1)
        self.assertIsInstance(inner.true_body[0], IRCall)
        self.assertEqual(inner.true_body[0].target, "exec")

    def test_provenance_edge_on_access(self):
        acc = IRAccess(root=IRVar("req"), path=["body", "cmd"])
        assign = IRAssign(target="cmd", value=acc)
        fn = IRFunction(name="handler", params=["req"], file_path="test.ts", body=[assign])
        mod = IRModule(file_path="test.ts", language="TypeScript", functions=[fn])
        mod.add_edge(acc.id, assign.id, "assign")
        mod2 = IRModule.from_json(mod.to_json())
        self.assertEqual(len(mod2.provenance_edges), 1)
        self.assertEqual(mod2.provenance_edges[0].source_id, acc.id)
        self.assertEqual(mod2.provenance_edges[0].target_id, assign.id)


class TestCallResolution(unittest.TestCase):

    def test_call_resolution_defaults(self):
        cr = CallResolution(call_id="CALL_abc", resolved_fn_id="FUNC_def")
        self.assertEqual(cr.call_id, "CALL_abc")
        self.assertEqual(cr.resolved_fn_id, "FUNC_def")
        self.assertEqual(cr.candidates, [])
        self.assertEqual(cr.confidence, 1.0)
        self.assertIsNone(cr.receiver_type)

    def test_call_resolution_full(self):
        cr = CallResolution(
            call_id="CALL_abc",
            resolved_fn_id="FUNC_def",
            candidates=["FUNC_def", "FUNC_ghi"],
            confidence=0.85,
            receiver_type="PRISMA_CLIENT",
        )
        self.assertEqual(len(cr.candidates), 2)
        self.assertEqual(cr.confidence, 0.85)
        self.assertEqual(cr.receiver_type, "PRISMA_CLIENT")

    def test_call_resolution_no_match(self):
        cr = CallResolution(call_id="CALL_abc", resolved_fn_id=None, candidates=[])
        self.assertIsNone(cr.resolved_fn_id)
        self.assertEqual(cr.candidates, [])

    def test_call_resolution_round_trip(self):
        cr = CallResolution(
            call_id="CALL_abc123",
            resolved_fn_id="FUNC_def456",
            candidates=["FUNC_def456", "FUNC_ghi789"],
            confidence=0.9,
            receiver_type="EXPRESS_REQUEST",
        )
        cr2 = CallResolution.from_dict(cr.to_dict())
        self.assertEqual(cr.call_id, cr2.call_id)
        self.assertEqual(cr.resolved_fn_id, cr2.resolved_fn_id)
        self.assertEqual(cr.candidates, cr2.candidates)
        self.assertEqual(cr.confidence, cr2.confidence)
        self.assertEqual(cr.receiver_type, cr2.receiver_type)


class TestIRModuleCallResolution(unittest.TestCase):

    def setUp(self):
        self.mod = IRModule(file_path="test.ts", language="TypeScript", functions=[])

    def test_add_resolution(self):
        self.mod.add_resolution(
            call_id="CALL_abc",
            resolved_fn_id="FUNC_def",
            candidates=["FUNC_def"],
            confidence=1.0,
        )
        self.assertEqual(len(self.mod.call_resolutions), 1)
        cr = self.mod.call_resolutions[0]
        self.assertEqual(cr.call_id, "CALL_abc")
        self.assertEqual(cr.resolved_fn_id, "FUNC_def")

    def test_add_resolution_without_fn_id(self):
        self.mod.add_resolution(call_id="CALL_abc")
        self.assertEqual(len(self.mod.call_resolutions), 1)
        self.assertIsNone(self.mod.call_resolutions[0].resolved_fn_id)

    def test_resolutions_in_json_round_trip(self):
        self.mod.add_resolution(
            call_id="CALL_abc",
            resolved_fn_id="FUNC_def",
            candidates=["FUNC_def"],
            confidence=0.95,
            receiver_type="PRISMA_CLIENT",
        )
        self.mod.add_resolution(call_id="CALL_unresolved")
        mod2 = IRModule.from_json(self.mod.to_json())
        self.assertEqual(len(mod2.call_resolutions), 2)
        self.assertEqual(mod2.call_resolutions[0].resolved_fn_id, "FUNC_def")
        self.assertEqual(mod2.call_resolutions[0].confidence, 0.95)
        self.assertEqual(mod2.call_resolutions[0].receiver_type, "PRISMA_CLIENT")
        self.assertIsNone(mod2.call_resolutions[1].resolved_fn_id)

    def test_empty_resolutions_in_json(self):
        mod2 = IRModule.from_json(self.mod.to_json())
        self.assertEqual(len(mod2.call_resolutions), 0)

    def test_resolutions_with_functions_round_trip(self):
        fn = IRFunction(name="handler", params=[], file_path="test.ts", body=[])
        self.mod.functions.append(fn)
        self.mod.add_resolution(call_id="CALL_abc", resolved_fn_id=fn.id)
        mod2 = IRModule.from_json(self.mod.to_json())
        self.assertEqual(len(mod2.functions), 1)
        self.assertEqual(len(mod2.call_resolutions), 1)
        self.assertEqual(mod2.functions[0].id, fn.id)


class TestProvenanceBuilder(unittest.TestCase):

    def test_provenance_from_assign(self):
        from extractors.js_ts import JsTsExtractor
        source = """
function test() {
  const x = y;
}
"""
        mod = JsTsExtractor().extract(source, "test.ts", "TypeScript")
        self.assertGreater(len(mod.provenance_edges), 0)
        # Should have an edge from VAR_y to ASSIGN_x
        edge = mod.provenance_edges[0]
        self.assertEqual(edge.transform, "assign")

    def test_provenance_from_call_assign(self):
        from extractors.js_ts import JsTsExtractor
        source = """
function test() {
  const result = getData();
}
"""
        mod = JsTsExtractor().extract(source, "test.ts", "TypeScript")
        edges = mod.provenance_edges
        # Should have edges: from VAR/arg to call, from call to assign
        self.assertGreater(len(edges), 0)

    def test_provenance_from_return(self):
        from extractors.js_ts import JsTsExtractor
        source = """
function test() {
  return x;
}
"""
        mod = JsTsExtractor().extract(source, "test.ts", "TypeScript")
        edges = mod.provenance_edges
        return_edges = [e for e in edges if e.transform == "return"]
        self.assertEqual(len(return_edges), 1)
        self.assertEqual(return_edges[0].transform, "return")

    def test_provenance_in_branch(self):
        from extractors.js_ts import JsTsExtractor
        source = """
function test(x) {
  if (x > 0) {
    const y = x;
  }
}
"""
        mod = JsTsExtractor().extract(source, "test.ts", "TypeScript")
        edges = mod.provenance_edges
        # The assign inside branch should have conditions set
        assign_edges = [e for e in edges if e.transform == "assign"]
        self.assertGreater(len(assign_edges), 0)
        # Should have conditions since assign is inside branch
        self.assertIsNotNone(assign_edges[-1].conditions)

    def test_provenance_no_edges_for_literal(self):
        from extractors.js_ts import JsTsExtractor
        source = """
function test() {
  const x = 42;
}
"""
        mod = JsTsExtractor().extract(source, "test.ts", "TypeScript")
        # Literal assignment should not create edges (no variable sources)
        var_edges = [e for e in mod.provenance_edges if e.source_id.startswith("VAR_")]
        self.assertEqual(len(var_edges), 0)


class TestSymbolResolver(unittest.TestCase):

    def test_resolve_same_module(self):
        from extractors.resolver import SymbolResolver
        fn = IRFunction(
            name="getUser",
            params=["id"],
            file_path="test.ts",
            body=[
                IRCall(target="helper", args=[IRVar("id")], result_var="result"),
                IRReturn(value=IRVar("result")),
            ],
        )
        helper = IRFunction(
            name="helper",
            params=["x"],
            file_path="test.ts",
            body=[IRReturn(value=IRLiteral(42, "number"))],
        )
        mod = IRModule(file_path="test.ts", language="TypeScript", functions=[fn, helper])
        resolver = SymbolResolver([mod])
        resolver.resolve_all()
        self.assertEqual(len(mod.call_resolutions), 1)
        cr = mod.call_resolutions[0]
        self.assertEqual(cr.resolved_fn_id, helper.id)

    def test_resolve_cross_module(self):
        from extractors.resolver import SymbolResolver
        fn1 = IRFunction(
            name="helper",
            params=["x"],
            file_path="src/helpers.ts",
            body=[IRReturn(value=IRVar("x"))],
        )
        mod1 = IRModule(file_path="src/helpers.ts", language="TypeScript", functions=[fn1])
        fn2 = IRFunction(
            name="handler",
            params=["id"],
            file_path="src/main.ts",
            body=[IRCall(target="helper", args=[IRVar("id")])],
        )
        mod2 = IRModule(file_path="src/main.ts", language="TypeScript", functions=[fn2])
        resolver = SymbolResolver([mod1, mod2])
        resolver.resolve_all()
        self.assertEqual(len(mod2.call_resolutions), 1)
        cr = mod2.call_resolutions[0]
        self.assertEqual(cr.resolved_fn_id, fn1.id)
        self.assertEqual(cr.confidence, 1.0)

    def test_resolve_nonexistent_returns_no_match(self):
        from extractors.resolver import SymbolResolver
        fn = IRFunction(
            name="handler",
            params=["id"],
            file_path="test.ts",
            body=[IRCall(target="doesNotExist", args=[IRVar("id")])],
        )
        mod = IRModule(file_path="test.ts", language="TypeScript", functions=[fn])
        resolver = SymbolResolver([mod])
        resolver.resolve_all()
        self.assertEqual(len(mod.call_resolutions), 0)

    def test_resolve_inline_call_expr(self):
        from extractors.resolver import SymbolResolver
        fn1 = IRFunction(
            name="helper",
            params=["x"],
            file_path="test.ts",
            body=[IRReturn(value=IRVar("x"))],
        )
        fn2 = IRFunction(
            name="handler",
            params=["id"],
            file_path="test.ts",
            body=[
                IRAssign(target="result", value=IRCallExpr(target="helper", args=[IRVar("id")])),
            ],
        )
        mod = IRModule(file_path="test.ts", language="TypeScript", functions=[fn1, fn2])
        resolver = SymbolResolver([mod])
        resolver.resolve_all()
        self.assertEqual(len(mod.call_resolutions), 1)
        cr = mod.call_resolutions[0]
        self.assertEqual(cr.resolved_fn_id, fn1.id)


if __name__ == "__main__":
    unittest.main()
