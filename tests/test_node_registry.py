"""Unit tests for global NODE_REGISTRY and human-readable path trace resolution."""

import pytest
from ir import IRVar, IRAccess, IRCallExpr, IRLiteral, IRCall, IRAssign, NODE_REGISTRY
from extractors.js_ts import JsTsExtractor
from extractors.call_graph import CallGraph
from extractors.taint_engine import TaintEngine
from security_graph import build_security_graph_from_ir, get_node_human_label, build_node_index


def test_node_registry_populates_on_creation():
    """Verify that creating IR nodes registers human-readable labels."""
    v = IRVar("user_input")
    assert v.id in NODE_REGISTRY
    assert NODE_REGISTRY[v.id][1] == "user_input"

    lit = IRLiteral("secret", "string")
    assert lit.id in NODE_REGISTRY
    assert NODE_REGISTRY[lit.id][1] == "secret"

    call = IRCallExpr("sanitize", [v])
    assert call.id in NODE_REGISTRY
    assert "sanitize" in NODE_REGISTRY[call.id][1]


def test_path_labels_contain_no_raw_hash_ids():
    """Verify that build_security_graph_from_ir produces path labels without raw hashes."""
    source_code = """
    function handleRequest(req) {
        const body = req.body;
        const normalized = normalizeRole(body);
        db.query(normalized);
    }
    """
    extractor = JsTsExtractor()
    mod = extractor.extract(source_code, "routes/auth.js", "JavaScript")
    assert mod is not None

    cg = CallGraph([mod])
    te = TaintEngine([mod], cg)
    paths = te.run()
    assert len(paths) >= 1

    sg = build_security_graph_from_ir([mod], cg, paths)
    flow = sg["flows"][0]
    path_labels = flow["path_labels"]

    # Verify no raw hash IDs (e.g. VAR_*, ACCESS_*, CALLE_*, ASSIGN_*) remain
    hash_prefixes = ("VAR_", "ACCESS_", "CALLE_", "ASSIGN_", "LIT_")
    for step in path_labels:
        for prefix in hash_prefixes:
            assert not step.startswith(prefix), f"Found raw hash string in step: {step}"
