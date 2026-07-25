import unittest
import sys
import os
import json

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from llm_detector import run_llm_detection

class MockDetectorClient:
    def __init__(self, response_text):
        self.response_text = response_text
        self.model = "mock-model"
        self.calls = []

    def complete(self, prompt, max_tokens=1000, stream=False):
        self.calls.append(prompt)
        return self.response_text

    def is_available(self):
        return True

class TestLLMDetector(unittest.TestCase):
    def test_run_llm_detection_vulnerable(self):
        mock_response = json.dumps({
            "vulnerable": True,
            "vulnerability_type": "SQL Injection",
            "severity": "high",
            "description": "SQL injection detected.",
            "trace": "Trace detail",
            "recommendation": "Use parameterized queries."
        })
        
        mock_client = MockDetectorClient(mock_response)
        
        security_graph = {
            "flows": [
                {
                    "id": "flow-0",
                    "source": "username",
                    "sink": "db.query",
                    "sink_type": "SINK_DATABASE",
                    "path": ["src/index.js::handler", "src/index.js::db.query"],
                    "path_labels": ["username", "db.query"],
                    "expressions": ["db.query(username)"]
                }
            ]
        }
        
        # We pass a dummy repo name. Since it won't find the folder in clones,
        # it won't read files but let's check how run_llm_detection handles it.
        # If files_content is empty, it skips. So let's mock open/exists or temporarily create a mock file in clones.
        repo_name = "mock_repo_test"
        clones_dir = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "clones", repo_name)
        os.makedirs(clones_dir, exist_ok=True)
        
        mock_file = os.path.join(clones_dir, "src", "index.js")
        os.makedirs(os.path.dirname(mock_file), exist_ok=True)
        with open(mock_file, "w", encoding="utf-8") as f:
            f.write("const username = req.body.username; db.query(username);")
            
        try:
            findings = run_llm_detection(repo_name, security_graph, mock_client, verbose=False)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["title"], "SQL Injection")
            self.assertEqual(findings[0]["severity"], "high")
            self.assertIn("SQL injection detected.", findings[0]["description"])
        finally:
            # Cleanup
            if os.path.exists(mock_file):
                os.remove(mock_file)
            if os.path.exists(clones_dir):
                import shutil
                shutil.rmtree(clones_dir)

if __name__ == "__main__":
    unittest.main()
