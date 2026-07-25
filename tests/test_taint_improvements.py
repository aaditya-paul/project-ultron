"""Unit tests for sink pattern precision and field-sensitive taint tracking improvements."""

import pytest
from extractors.taint_engine import detect_sink_type, TaintEngine, TaintPath
from extractors.js_ts import JsTsExtractor
from extractors.call_graph import CallGraph
from ir import IRModule, IRFunction, IRVar, IRAccess, IRAssign, IRCall, Tag, Edge


def test_standard_js_methods_not_flagged_as_sinks():
    """Verify built-in array/object methods are not misclassified as DB sinks."""
    assert detect_sink_type("find") is None
    assert detect_sink_type("filter") is None
    assert detect_sink_type("map") is None
    assert detect_sink_type("Object.create") is None
    assert detect_sink_type("JSON.parse") is None
    assert detect_sink_type("select") is None


def test_graphics_and_dom_methods_excluded():
    """Verify WebGL, 3D math, and DOM methods are excluded from being flagged as sinks."""
    assert detect_sink_type("normalize") is None
    assert detect_sink_type("transform") is None
    assert detect_sink_type("uniform1f") is None
    assert detect_sink_type("uniformMatrix4fv") is None
    assert detect_sink_type("querySelector") is None
    assert detect_sink_type("fromQueryParams") is None
    assert detect_sink_type("getErrorMessage") is None
    assert detect_sink_type("streamText") is None


def test_actual_db_methods_flagged_as_sinks():
    """Verify actual database calls are accurately identified as DB sinks."""
    assert detect_sink_type("db.query") == ("SINK_DATABASE", 0.85)
    assert detect_sink_type("prisma.user.findFirst") == ("SINK_DATABASE", 0.85)
    assert detect_sink_type("knex('users').select") == ("SINK_DATABASE", 0.85)
    assert detect_sink_type("User.findOne") == ("SINK_DATABASE", 0.85)


def test_field_sensitive_provenance():
    """Verify property access assignment creates matching IRAccess node edges."""
    source_code = """
    function handle(req) {
        const user = {};
        user.name = req.body.name;
        db.query(user.name);
    }
    """
    extractor = JsTsExtractor()
    mod = extractor.extract(source_code, "test.js", "JavaScript")
    assert mod is not None

    cg = CallGraph([mod])
    te = TaintEngine([mod], cg)
    paths = te.run()

    assert len(paths) >= 1
    p = paths[0]
    assert p.sink_type == "SINK_DATABASE"
    assert p.source_tag in ("SOURCE_HTTP_BODY", "HTTP_BODY")


def test_non_runtime_file_exclusion():
    """Verify test configs, build files, and vendor assets are ignored in sink collection."""
    from extractors.taint_engine import is_non_runtime_file
    assert is_non_runtime_file("cypress.config.ts") is True
    assert is_non_runtime_file("Gruntfile.js") is True
    assert is_non_runtime_file("frontend/src/assets/private/three.js") is True
    assert is_non_runtime_file("routes/login.ts") is False
    assert is_non_runtime_file("controllers/user.js") is False
