import unittest
import sys
import os

# Add parent directory to path to import classifier/features
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from features import FunctionFeatures
from classifier import PatternPass, parse_response, HybridClassifier

class MockLLMClient:
    def __init__(self, response_text):
        self.response_text = response_text
        self.calls = []

    def complete(self, prompt, max_tokens=100):
        self.calls.append(prompt)
        return self.response_text

    def batch_complete(self, prompts, max_tokens=100):
        self.calls.extend(prompts)
        return [self.response_text] * len(prompts)

class TestClassifier(unittest.TestCase):
    def test_pattern_pass(self):
        pp = PatternPass()
        
        # Test Source
        feat_src = FunctionFeatures(
            name="handleRequest",
            file_path="server.js",
            line=1,
            language="JavaScript",
            params=["req", "res"],
            param_count=2,
            body_text="",
            calls_made=[],
            assignments=[],
            returns=[],
            field_accesses=["req.body"],
            file_imports=[],
            calls_to_this=[],
            called_by_this=[],
            is_exported=True,
            is_async=False,
            is_in_route_file=True,
            has_error_handling=False
        )
        res = pp.classify(feat_src)
        self.assertIsNotNone(res)
        self.assertEqual(res.label, "SOURCE")
        self.assertEqual(res.by, "pattern")

        # Test DB Sink
        feat_db = FunctionFeatures(
            name="saveUser",
            file_path="db.js",
            line=1,
            language="JavaScript",
            params=["user"],
            param_count=1,
            body_text="",
            calls_made=["db.users.insert(user)"],
            assignments=[],
            returns=[],
            field_accesses=[],
            file_imports=[],
            calls_to_this=[],
            called_by_this=[],
            is_exported=True,
            is_async=False,
            is_in_route_file=False,
            has_error_handling=False
        )
        res = pp.classify(feat_db)
        self.assertIsNotNone(res)
        self.assertEqual(res.label, "SINK_DATABASE")
        self.assertEqual(res.by, "pattern")

    def test_parse_response(self):
        label, conf = parse_response("SINK_DATABASE 0.85")
        self.assertEqual(label, "SINK_DATABASE")
        self.assertEqual(conf, 0.85)

        label, conf = parse_response("The classification is AUTH with confidence 0.9.")
        self.assertEqual(label, "AUTH")
        self.assertEqual(conf, 0.9)

        label, conf = parse_response("INVALID_LABEL 1.5")
        self.assertEqual(label, "NONE")
        self.assertEqual(conf, 0.80) # Default confidence

    def test_hybrid_classifier_fallback(self):
        # Without LLM, should fallback to NONE for unclassified pattern
        feat = FunctionFeatures(
            name="helper",
            file_path="utils.js",
            line=1,
            language="JavaScript",
            params=[],
            param_count=0,
            body_text="",
            calls_made=[],
            assignments=[],
            returns=[],
            field_accesses=[],
            file_imports=[],
            calls_to_this=[],
            called_by_this=[],
            is_exported=True,
            is_async=False,
            is_in_route_file=False,
            has_error_handling=False
        )
        
        hc = HybridClassifier(None)
        results = hc.classify_all([feat])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1].label, "NONE")

    def test_hybrid_classifier_llm(self):
        # With LLM, should query the LLM
        feat = FunctionFeatures(
            name="process",
            file_path="process.js",
            line=1,
            language="JavaScript",
            params=["data"],
            param_count=1,
            body_text="db.query(data);",
            calls_made=[],
            assignments=[],
            returns=[],
            field_accesses=[],
            file_imports=[],
            calls_to_this=[],
            called_by_this=[],
            is_exported=True,
            is_async=False,
            is_in_route_file=False,
            has_error_handling=False
        )
        
        mock_client = MockLLMClient("SINK_DATABASE 0.95")
        hc = HybridClassifier(mock_client)
        results = hc.classify_all([feat])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1].label, "SINK_DATABASE")
        self.assertEqual(results[0][1].confidence, 0.95)
        self.assertEqual(results[0][1].by, "llm")
        self.assertEqual(len(mock_client.calls), 1)

if __name__ == "__main__":
    unittest.main()
