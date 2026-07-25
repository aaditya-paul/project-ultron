import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ir import (
    IRModule, IRFunction, IRCall, IRVar, IRAccess, IRLiteral,
    IRAssign, IRBranch, IRReturn, IRCallExpr, Edge, Tag, CallResolution,
)
from extractors.call_graph import CallGraph
from extractors.taint_engine import TaintEngine, TaintPath, detect_sink_type, matches_any_glob


class TestCallGraphConstruction(unittest.TestCase):

    def test_empty(self):
        cg = CallGraph([])
        self.assertEqual(len(cg.all_functions()), 0)
        self.assertEqual(cg.summary(), "CallGraph: 0 functions, 0 call edges")

    def test_single_call(self):
        caller = IRFunction(name="handler", params=[], file_path="a.ts", body=[
            IRCall(target="helper", args=[], id="CALL_001"),
        ])
        callee = IRFunction(name="helper", params=[], file_path="a.ts", body=[])
        mod = IRModule(file_path="a.ts", language="TypeScript", functions=[caller, callee])
        mod.call_resolutions.append(CallResolution(
            call_id="CALL_001", resolved_fn_id=callee.id,
        ))
        cg = CallGraph([mod])
        self.assertIn(caller.id, cg.all_functions())
        self.assertIn(callee.id, cg.all_functions())
        self.assertIn(callee.id, cg.get_callees(caller.id))
        self.assertIn(caller.id, cg.get_callers(callee.id))

    def test_cross_module(self):
        mod1 = IRModule(file_path="helpers.ts", language="TypeScript", functions=[
            IRFunction(name="helper", params=[], file_path="helpers.ts", body=[], id="FUNC_helper"),
        ])
        mod2 = IRModule(file_path="main.ts", language="TypeScript", functions=[
            IRFunction(name="handler", params=[], file_path="main.ts", body=[
                IRCall(target="helper", args=[], id="CALL_001"),
            ], id="FUNC_handler"),
        ])
        mod2.call_resolutions.append(CallResolution(call_id="CALL_001", resolved_fn_id="FUNC_helper"))
        cg = CallGraph([mod1, mod2])
        self.assertIn("FUNC_helper", cg.get_callees("FUNC_handler"))
        self.assertIn("FUNC_handler", cg.get_callers("FUNC_helper"))

    def test_fn_metadata(self):
        fn = IRFunction(name="getUser", params=["id"], file_path="users.ts", body=[])
        mod = IRModule(file_path="users.ts", language="TypeScript", functions=[fn])
        cg = CallGraph([mod])
        self.assertEqual(cg.fn_name(fn.id), "getUser")
        self.assertEqual(cg.fn_file(fn.id), "users.ts")

    def test_serialization_round_trip(self):
        fn_a = IRFunction(name="a", params=[], file_path="x.ts", body=[
            IRCall(target="b", args=[], id="CALL_a"),
        ], id="FUNC_a")
        fn_b = IRFunction(name="b", params=[], file_path="x.ts", body=[], id="FUNC_b")
        mod = IRModule(file_path="x.ts", language="TypeScript", functions=[fn_a, fn_b])
        mod.call_resolutions.append(CallResolution(call_id="CALL_a", resolved_fn_id="FUNC_b"))
        cg1 = CallGraph([mod])
        data = cg1.to_dict()
        cg2 = CallGraph.from_dict(data)
        self.assertEqual(len(cg2.all_functions()), 2)
        self.assertIn("FUNC_b", cg2.get_callees("FUNC_a"))


class TestCallGraphPaths(unittest.TestCase):

    def test_direct_call(self):
        mod = IRModule(file_path="x.ts", language="TypeScript", functions=[
            IRFunction(name="a", params=[], file_path="x.ts", body=[IRCall(target="b", args=[], id="CALL_ab")], id="FUNC_a"),
            IRFunction(name="b", params=[], file_path="x.ts", body=[], id="FUNC_b"),
            IRFunction(name="c", params=[], file_path="x.ts", body=[], id="FUNC_c"),
        ])
        mod.call_resolutions.append(CallResolution(call_id="CALL_ab", resolved_fn_id="FUNC_b"))
        cg = CallGraph([mod])
        paths = cg.paths_between("FUNC_a", "FUNC_b")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], ["FUNC_a", "FUNC_b"])

    def test_indirect_chain(self):
        mod = IRModule(file_path="x.ts", language="TypeScript", functions=[
            IRFunction(name="a", params=[], file_path="x.ts", body=[IRCall(target="b", args=[], id="CALL_ab")], id="FUNC_a"),
            IRFunction(name="b", params=[], file_path="x.ts", body=[IRCall(target="c", args=[], id="CALL_bc")], id="FUNC_b"),
            IRFunction(name="c", params=[], file_path="x.ts", body=[], id="FUNC_c"),
        ])
        mod.call_resolutions.append(CallResolution(call_id="CALL_ab", resolved_fn_id="FUNC_b"))
        mod.call_resolutions.append(CallResolution(call_id="CALL_bc", resolved_fn_id="FUNC_c"))
        cg = CallGraph([mod])
        paths = cg.paths_between("FUNC_a", "FUNC_c")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], ["FUNC_a", "FUNC_b", "FUNC_c"])

    def test_no_path_returns_empty(self):
        mod = IRModule(file_path="x.ts", language="TypeScript", functions=[
            IRFunction(name="a", params=[], file_path="x.ts", body=[], id="FUNC_a"),
            IRFunction(name="b", params=[], file_path="x.ts", body=[], id="FUNC_b"),
        ])
        cg = CallGraph([mod])
        paths = cg.paths_between("FUNC_a", "FUNC_b")
        self.assertEqual(len(paths), 0)


class TestSinkDetection(unittest.TestCase):

    def test_db_sink(self):
        result = detect_sink_type("db.query")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "SINK_DATABASE")

    def test_shell_sink(self):
        result = detect_sink_type("child_process.exec")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "SINK_SHELL")

    def test_file_sink(self):
        result = detect_sink_type("fs.readFileSync")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "SINK_FILE")

    def test_network_sink(self):
        result = detect_sink_type("axios.get")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "SINK_NETWORK")

    def test_safe_call_no_sink(self):
        result = detect_sink_type("console.log")
        self.assertIsNone(result)
        result = detect_sink_type("Math.max")
        self.assertIsNone(result)

    def test_matches_any_glob(self):
        self.assertTrue(matches_any_glob("db.query", {"*db.*"}))
        self.assertTrue(matches_any_glob("prisma.user.findUnique", {"*prisma*"}))
        self.assertFalse(matches_any_glob("console.log", {"*db.*", "*exec*"}))


class TestTaintEngineBasic(unittest.TestCase):

    def test_taint_path_detected(self):
        """HTTP_BODY source → assign → sink call via provenance edges."""
        source_var = IRVar(name="req", id="VAR_req")
        id_var = IRVar("id")
        access = IRAccess(root=source_var, path=["body", "id"], id="ACCESS_body_id")
        assign = IRAssign(target="id", value=access, id="ASSIGN_id")
        sink_call = IRCall(target="db.query", args=[id_var], id="CALL_query")

        fn = IRFunction(
            name="handler", params=["req"], file_path="api.ts",
            body=[assign, sink_call],
        )
        mod = IRModule(file_path="api.ts", language="TypeScript", functions=[fn])
        mod.add_edge(source_id=access.id, target_id=assign.id, transform="assign")
        mod.add_edge(source_id=assign.id, target_id=id_var.id, transform="assign_target")
        mod.add_edge(source_id=id_var.id, target_id=sink_call.id, transform="arg")
        mod.add_tag("HTTP_BODY", access.id)

        from extractors.call_graph import CallGraph
        cg = CallGraph([mod])
        te = TaintEngine([mod], cg)
        paths = te.run()

        self.assertGreater(len(paths), 0)
        p = paths[0]
        self.assertEqual(p.source_tag, "HTTP_BODY")
        self.assertEqual(p.sink_target, "db.query")
        self.assertFalse(p.sanitized)
        self.assertIn(access.id, p.path_node_ids)

    def test_no_taint_without_source_tag(self):
        """No source tag → no taint paths."""
        x_var = IRVar("x")
        sink_call = IRCall(target="db.query", args=[x_var], id="CALL_query")
        fn = IRFunction(name="handler", params=["x"], file_path="api.ts", body=[sink_call])
        mod = IRModule(file_path="api.ts", language="TypeScript", functions=[fn])
        mod.add_edge(source_id=x_var.id, target_id=sink_call.id, transform="arg")

        cg = CallGraph([mod])
        te = TaintEngine([mod], cg)
        paths = te.run()
        self.assertEqual(len(paths), 0)

    def test_multiple_sinks(self):
        """Multiple sinks should produce multiple paths."""
        source_var = IRVar(name="req", id="VAR_req")
        input_var = IRVar("input")
        access = IRAccess(root=source_var, path=["input"], id="ACCESS_input")
        assign = IRAssign(target="input", value=access, id="ASSIGN_input")
        sink1 = IRCall(target="db.query", args=[input_var], id="CALL_query")
        sink2 = IRCall(target="fs.writeFile", args=[input_var], id="CALL_write")

        fn = IRFunction(
            name="handler", params=["req"], file_path="api.ts",
            body=[assign, sink1, sink2],
        )
        mod = IRModule(file_path="api.ts", language="TypeScript", functions=[fn])
        mod.add_edge(access.id, assign.id, "assign")
        mod.add_edge(assign.id, input_var.id, "assign_target")
        mod.add_edge(input_var.id, sink1.id, "arg")
        mod.add_edge(input_var.id, sink2.id, "arg")
        mod.add_tag("HTTP_BODY", access.id)

        cg = CallGraph([mod])
        te = TaintEngine([mod], cg)
        paths = te.run()
        self.assertEqual(len(paths), 2)

    def test_sink_in_call_expr(self):
        """Sink detected inside an IRCallExpr within an assignment."""
        x_var = IRVar("x")
        ce = IRCallExpr(target="db.query", args=[x_var], id="CALLE_query")
        assign = IRAssign(target="result", value=ce, id="ASSIGN_result")

        fn = IRFunction(name="getData", params=["x"], file_path="api.ts", body=[assign])
        mod = IRModule(file_path="api.ts", language="TypeScript", functions=[fn])
        mod.add_edge(x_var.id, ce.id, "arg")
        mod.add_tag("HTTP_PARAMS", x_var.id)

        cg = CallGraph([mod])
        te = TaintEngine([mod], cg)
        paths = te.run()
        self.assertGreater(len(paths), 0)
        self.assertEqual(paths[0].sink_target, "db.query")


class TestTaintEngineSanitized(unittest.TestCase):

    def test_sanitized_by_validation_gate(self):
        """VALDATION_GATE tag on variable sanitizes the path."""
        source_var = IRVar(name="req", id="VAR_req")
        access = IRAccess(root=source_var, path=["body", "input"], id="ACCESS_input")
        input_var = IRVar("input")
        assign = IRAssign(target="input", value=access, id="ASSIGN_input")
        sink = IRCall(target="db.query", args=[input_var], id="CALL_query")

        fn = IRFunction(
            name="handler", params=["req"], file_path="api.ts",
            body=[assign, sink],
        )
        mod = IRModule(file_path="api.ts", language="TypeScript", functions=[fn])
        mod.add_edge(access.id, assign.id, "assign")
        mod.add_edge(assign.id, input_var.id, "assign_target")
        mod.add_edge(input_var.id, sink.id, "arg")
        mod.add_tag("HTTP_BODY", access.id)
        # VALIDATION_GATE on the variable node — marks the path as sanitized
        mod.add_tag("VALIDATION_GATE", input_var.id)

        cg = CallGraph([mod])
        te = TaintEngine([mod], cg)
        paths = te.run()
        self.assertGreater(len(paths), 0)
        self.assertTrue(any(p.sanitized for p in paths))

    def test_mixed_sanitized_and_unsanitized(self):
        """Both sanitized and unsanitized paths from different sources."""
        src1 = IRAccess(root=IRVar("req", id="VAR_req"), path=["safe"], id="ACCESS_safe")
        src2 = IRAccess(root=IRVar("req", id="VAR_req"), path=["raw"], id="ACCESS_raw")
        safe_var = IRVar("safe_val")
        raw_var = IRVar("raw_val")
        assign_safe = IRAssign(target="safe_val", value=src1, id="ASSIGN_safe")
        assign_raw = IRAssign(target="raw_val", value=src2, id="ASSIGN_raw")
        sink = IRCall(target="db.query", args=[safe_var, raw_var], id="CALL_query")

        fn = IRFunction(
            name="handler", params=["req"], file_path="api.ts",
            body=[assign_safe, assign_raw, sink],
        )
        mod = IRModule(file_path="api.ts", language="TypeScript", functions=[fn])
        mod.add_edge(src1.id, assign_safe.id, "assign")
        mod.add_edge(src2.id, assign_raw.id, "assign")
        mod.add_edge(assign_safe.id, safe_var.id, "assign_target")
        mod.add_edge(assign_raw.id, raw_var.id, "assign_target")
        mod.add_edge(safe_var.id, sink.id, "arg")
        mod.add_edge(raw_var.id, sink.id, "arg")
        mod.add_tag("HTTP_BODY", src1.id)
        mod.add_tag("HTTP_BODY", src2.id)
        # VALIDATION_GATE on the safe variable (src1 → safe_val is sanitized)
        mod.add_tag("VALIDATION_GATE", safe_var.id)

        cg = CallGraph([mod])
        te = TaintEngine([mod], cg)
        paths = te.run()
        self.assertEqual(len(paths), 2)


class TestTaintEngineDedup(unittest.TestCase):

    def test_dedup_same_source_sink(self):
        """Same (source, sink) pair deduplicated."""
        access = IRAccess(root=IRVar("req", id="VAR_req"), path=["body", "x"], id="ACCESS_x")
        x_var = IRVar("x")
        assign = IRAssign(target="x", value=access, id="ASSIGN_x")
        sink = IRCall(target="db.query", args=[x_var], id="CALL_query")

        fn = IRFunction(
            name="handler", params=["req"], file_path="api.ts",
            body=[assign, sink],
        )
        mod = IRModule(file_path="api.ts", language="TypeScript", functions=[fn])
        mod.add_edge(access.id, assign.id, "assign")
        mod.add_edge(access.id, assign.id, "assign")  # duplicate edge
        mod.add_edge(assign.id, x_var.id, "assign_target")
        mod.add_edge(x_var.id, sink.id, "arg")
        mod.add_tag("HTTP_BODY", access.id)

        cg = CallGraph([mod])
        te = TaintEngine([mod], cg)
        paths = te.run()
        self.assertEqual(len(paths), 1)


class TestTaintEngineCrossModule(unittest.TestCase):

    def test_cross_module_call_chain(self):
        """Taint flows through a cross-module call: handler → getUser → db.query."""
        id_var = IRVar("id")
        result_var = IRVar("result")

        # Module 2: getUser calls db.query
        sink = IRCall(target="db.query", args=[id_var], id="CALL_query")
        ret = IRReturn(value=result_var, id="RET_getUser")
        helper_fn = IRFunction(
            name="getUser", params=["id"], file_path="db.ts",
            body=[sink, ret], id="FUNC_getUser",
        )
        mod2 = IRModule(file_path="db.ts", language="TypeScript", functions=[helper_fn])
        mod2.add_edge(id_var.id, sink.id, "arg")

        # Module 1: handler receives req, calls getUser
        access = IRAccess(root=IRVar("req", id="VAR_req"), path=["body", "id"], id="ACCESS_body_id")
        userId_var = IRVar("userId")
        assign = IRAssign(target="userId", value=access, id="ASSIGN_userId")
        call = IRCall(target="getUser", args=[userId_var], id="CALL_getUser")

        handler_fn = IRFunction(
            name="handler", params=["req"], file_path="api.ts",
            body=[assign, call], id="FUNC_handler",
        )
        mod1 = IRModule(file_path="api.ts", language="TypeScript", functions=[handler_fn])
        mod1.add_edge(access.id, assign.id, "assign")
        mod1.add_edge(assign.id, userId_var.id, "assign_target")
        mod1.add_edge(userId_var.id, call.id, "arg")
        mod1.add_tag("HTTP_BODY", access.id)
        mod1.call_resolutions.append(CallResolution(
            call_id="CALL_getUser", resolved_fn_id="FUNC_getUser",
        ))

        cg = CallGraph([mod1, mod2])
        te = TaintEngine([mod1, mod2], cg)
        paths = te.run()

        self.assertGreater(len(paths), 0)
        p = paths[0]
        self.assertEqual(p.source_tag, "HTTP_BODY")
        self.assertEqual(p.sink_target, "db.query")


if __name__ == "__main__":
    unittest.main()
