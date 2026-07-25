import unittest
import sys
import os

# Add parent directory to path to import taint/entities
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from taint import TaintRunner, TaintedVar, TaintEdge, TaintPath

class TestTaint(unittest.TestCase):
    def test_taint_propagation_basic(self):
        # A simple JS file that takes request input, assigns it to a variable, and queries DB
        ast_data = {
            "files": {
                "server.js": {
                    "language": "JavaScript",
                    "imports": ["db"],
                    "functions": [
                        {
                            "name": "handler",
                            "params": ["req", "res"],
                            "line": 1,
                            "end_line": 10,
                            "anonymous": False,
                            "body_text": "const query = req.body.q; db.query(query);"
                        }
                    ],
                    "assignments": [
                        {"target": "query", "value_text": "req.body.q", "line": 3}
                    ],
                    "returns": [],
                    "field_accesses": [
                        {"full_text": "req.body.q", "line": 3}
                    ],
                    "calls": [
                        {"text": "db.query(query)", "line": 5}
                    ]
                }
            }
        }

        # Manually construct classified entities
        entities = [
            {
                "type": "SOURCE",
                "label": "param:req",
                "file": "server.js",
                "line": 1,
                "fnid": "server.js::handler",
                "metadata": {}
            },
            {
                "type": "SINK_DATABASE",
                "label": "db.query",
                "file": "server.js",
                "line": 5,
                "fnid": "server.js::handler",
                "metadata": {"confidence": 0.90}
            }
        ]

        known_funcs = {
            "server.js::handler": {
                "name": "handler",
                "file": "server.js",
                "line": 1,
                "params": ["req", "res"],
                "calls": [{"text": "db.query(query)", "line": 5}]
            }
        }

        runner = TaintRunner(ast_data, entities, known_funcs)
        paths = runner.run()

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path.source.name, "req")
        self.assertEqual(path.sink_call, "db.query(query)")
        self.assertEqual(path.sink_type, "SINK_DATABASE")
        self.assertFalse(path.sanitized)
        self.assertEqual(len(path.edges), 1)
        self.assertEqual(path.edges[0].from_var, "req")
        self.assertEqual(path.edges[0].to_var, "query")

    def test_taint_propagation_sanitized(self):
        # A JS file that takes request input, validates it, and queries DB
        ast_data = {
            "files": {
                "server.js": {
                    "language": "JavaScript",
                    "imports": ["db", "validator"],
                    "functions": [
                        {
                            "name": "handler",
                            "params": ["req", "res"],
                            "line": 1,
                            "end_line": 10,
                            "anonymous": False,
                            "body_text": "const clean = validate(req.body.q); db.query(clean);"
                        }
                    ],
                    "assignments": [
                        {"target": "clean", "value_text": "validate(req.body.q)", "line": 3}
                    ],
                    "returns": [],
                    "field_accesses": [
                        {"full_text": "req.body.q", "line": 3}
                    ],
                    "calls": [
                        {"text": "validate(req.body.q)", "line": 3},
                        {"text": "db.query(clean)", "line": 5}
                    ]
                }
            }
        }

        entities = [
            {
                "type": "SOURCE",
                "label": "param:req",
                "file": "server.js",
                "line": 1,
                "fnid": "server.js::handler",
                "metadata": {}
            },
            {
                "type": "VALIDATION",
                "label": "validate",
                "file": "server.js",
                "line": 3,
                "fnid": "server.js::handler",
                "metadata": {}
            },
            {
                "type": "SINK_DATABASE",
                "label": "db.query",
                "file": "server.js",
                "line": 5,
                "fnid": "server.js::handler",
                "metadata": {"confidence": 0.90}
            }
        ]

        known_funcs = {
            "server.js::handler": {
                "name": "handler",
                "file": "server.js",
                "line": 1,
                "params": ["req", "res"],
                "calls": [{"text": "validate(req.body.q)", "line": 3}, {"text": "db.query(clean)", "line": 5}]
            }
        }

        runner = TaintRunner(ast_data, entities, known_funcs)
        paths = runner.run()

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertTrue(path.sanitized)
        self.assertIn("validate", path.sanitizers)

if __name__ == "__main__":
    unittest.main()
