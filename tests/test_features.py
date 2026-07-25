import unittest
import sys
import os

# Add parent directory to path to import features
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from features import extract_features

class TestFeatures(unittest.TestCase):
    def test_extract_features_basic(self):
        ast_data = {
            "files": {
                "src/routes/server.js": {
                    "language": "JavaScript",
                    "imports": ["express", "db"],
                    "functions": [
                        {
                            "name": "processData",
                            "params": ["req", "res"],
                            "line": 1,
                            "end_line": 10,
                            "anonymous": False,
                            "body_text": "const name = req.body.name; db.query(name);"
                        }
                    ],
                    "assignments": [
                        {"target": "name", "value_text": "req.body.name", "line": 3}
                    ],
                    "returns": [
                        {"value_text": "res.send(200)", "line": 8}
                    ],
                    "field_accesses": [
                        {"full_text": "req.body.name", "line": 3}
                    ],
                    "calls": [
                        {"text": "db.query(name)", "line": 5}
                    ]
                }
            }
        }
        
        features = extract_features(ast_data)
        self.assertEqual(len(features), 1)
        feat = features[0]
        self.assertEqual(feat.name, "processData")
        self.assertEqual(feat.file_path, "src/routes/server.js")
        self.assertEqual(feat.line, 1)
        self.assertEqual(feat.language, "JavaScript")
        self.assertEqual(feat.params, ["req", "res"])
        self.assertEqual(feat.param_count, 2)
        self.assertEqual(feat.calls_made, ["db.query(name)"])
        self.assertEqual(feat.assignments, [{"target": "name", "value": "req.body.name"}])
        self.assertEqual(feat.returns, ["res.send(200)"])
        self.assertEqual(feat.field_accesses, ["req.body.name"])
        self.assertEqual(feat.file_imports, ["express", "db"])
        self.assertTrue(feat.is_exported)
        self.assertFalse(feat.is_async)
        self.assertTrue(feat.is_in_route_file)

if __name__ == "__main__":
    unittest.main()
