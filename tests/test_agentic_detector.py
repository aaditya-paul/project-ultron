import unittest
import sys
import os
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from llm_detector import (
    GlobalMemory,
    run_llm_discovery,
    run_agentic_flow_analysis,
    run_consistency_reconciliation,
)

class MockDetectorClient:
    def __init__(self, responses):
        # responses is a list of strings to be returned in order of complete() calls
        self.responses = responses
        self.call_count = 0
        self.calls = []
        self.model = "agentic-mock-model"
        self.temperature = 0.1

    def complete(self, prompt, max_tokens=1000, stream=False):
        self.calls.append(prompt)
        if self.call_count < len(self.responses):
            res = self.responses[self.call_count]
            self.call_count += 1
            return res
        return ""

    def is_available(self):
        return True


class TestAgenticDetector(unittest.TestCase):

    def test_global_memory(self):
        memory = GlobalMemory()
        memory.add_fact("FACT 1")
        memory.add_fact("FACT 1")  # duplicate
        memory.add_fact("FACT 2")
        
        self.assertEqual(len(memory.facts), 2)
        self.assertIn("FACT 1", memory.facts)
        self.assertIn("FACT 2", memory.facts)
        
        memory.discovery_data = {"frameworks": ["Express"]}
        mem_str = memory.to_string()
        self.assertIn("FACT 1", mem_str)
        self.assertIn("Express", mem_str)

    def test_llm_discovery(self):
        mock_response = json.dumps({
            "frameworks": ["Express"],
            "database_client": "Prisma",
            "auth_mechanisms": ["JWT"],
            "validation_libraries": ["Zod"],
            "security_middlewares": ["Helmet"],
            "notes": "Test note"
        })
        client = MockDetectorClient([mock_response])
        
        # We can pass an empty target_path because it falls back gracefully or uses file listing
        memory = run_llm_discovery("/dummy/path", client, ir_modules=[])
        self.assertEqual(memory.discovery_data.get("database_client"), "Prisma")
        self.assertEqual(memory.discovery_data.get("validation_libraries"), ["Zod"])

    def test_agentic_flow_analysis_finish_immediately(self):
        finish_response = json.dumps({
            "action": "FINISH",
            "vulnerable": True,
            "vulnerability_type": "SQL Injection",
            "severity": "high",
            "description": "SQL injection via concatenation.",
            "trace": "trace flow info",
            "recommendation": "Use parameterization"
        })
        client = MockDetectorClient([finish_response])
        
        flow = {
            "id": "flow-1",
            "source": "username",
            "sink": "db.query",
            "sink_type": "SINK_DATABASE",
            "path": [],
            "path_labels": ["username", "db.query"],
            "expressions": []
        }
        
        memory = GlobalMemory()
        result = run_agentic_flow_analysis(
            target_path="/dummy/path",
            flow=flow,
            node_fn_map={},
            fn_boundaries={},
            global_memory=memory,
            detector_client=client,
            verbose=False
        )
        
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["vulnerability_type"], "SQL Injection")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["description"], "SQL injection via concatenation.")

    def test_agentic_flow_analysis_read_file_then_finish(self):
        read_action = json.dumps({
            "action": "READ_FILE",
            "path": "src/utils.js",
            "start_line": 1,
            "end_line": 10
        })
        finish_action = json.dumps({
            "action": "FINISH",
            "vulnerable": False,
            "vulnerability_type": "None",
            "severity": "none",
            "description": "Checked file and found zod validation.",
            "trace": "safe path",
            "recommendation": ""
        })
        client = MockDetectorClient([read_action, finish_action])
        
        flow = {
            "id": "flow-2",
            "source": "input",
            "sink": "db.query",
            "sink_type": "SINK_DATABASE",
            "path": [],
            "path_labels": ["input", "db.query"],
            "expressions": []
        }
        
        memory = GlobalMemory()
        result = run_agentic_flow_analysis(
            target_path="/dummy/path",
            flow=flow,
            node_fn_map={},
            fn_boundaries={},
            global_memory=memory,
            detector_client=client,
            verbose=False
        )
        
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["vulnerability_type"], "None")
        self.assertIn("Checked file", result["description"])
        self.assertEqual(client.call_count, 2)

    def test_agentic_flow_analysis_record_fact_then_finish(self):
        record_action = json.dumps({
            "action": "RECORD_FACT",
            "fact": "Project uses validation middleware in auth.js"
        })
        finish_action = json.dumps({
            "action": "FINISH",
            "vulnerable": False,
            "vulnerability_type": "None",
            "severity": "none",
            "description": "Validation middleware exists.",
            "trace": "safe path",
            "recommendation": ""
        })
        client = MockDetectorClient([record_action, finish_action])
        
        flow = {
            "id": "flow-3",
            "source": "input",
            "sink": "db.query",
            "sink_type": "SINK_DATABASE",
            "path": [],
            "path_labels": ["input", "db.query"],
            "expressions": []
        }
        
        memory = GlobalMemory()
        result = run_agentic_flow_analysis(
            target_path="/dummy/path",
            flow=flow,
            node_fn_map={},
            fn_boundaries={},
            global_memory=memory,
            detector_client=client,
            verbose=False
        )
        
        self.assertFalse(result["vulnerable"])
        self.assertIn("Project uses validation middleware in auth.js", memory.facts)

    def test_consistency_reconciliation_corrections(self):
        # We simulate consistency review corrections
        recon_response = json.dumps({
            "corrections": [
                {
                    "flow_id": "flow-100",
                    "original_vulnerable": False,
                    "corrected_vulnerable": True,
                    "reason": "Correcting flow-100 to vulnerable as it has the same unvalidated input path as flow-101."
                }
            ],
            "final_verdicts": [
                {
                    "flow_id": "flow-100",
                    "vulnerable": True,
                    "vulnerability_type": "SQL Injection",
                    "severity": "high",
                    "description": "SQL injection via dynamic query",
                    "recommendation": "Use parameterized queries"
                },
                {
                    "flow_id": "flow-101",
                    "vulnerable": True,
                    "vulnerability_type": "SQL Injection",
                    "severity": "high",
                    "description": "SQL injection via dynamic query",
                    "recommendation": "Use parameterized queries"
                }
            ]
        })
        client = MockDetectorClient([recon_response])
        
        findings = [
            {
                "rule": "sql-injection",
                "severity": "high",
                "title": "SQL Injection",
                "flow_id": "flow-101",
                "description": "original description flow 101",
                "source": "input",
                "sink": "db.query",
                "path": ["input", "db.query"],
                "recommendation": "Use parameterized queries"
            }
        ]
        
        processed_flows = [
            {
                "id": "flow-100",
                "source": "input",
                "sink": "db.query",
                "sink_type": "SINK_DATABASE",
                "path_labels": ["input", "db.query"]
            },
            {
                "id": "flow-101",
                "source": "input",
                "sink": "db.query",
                "sink_type": "SINK_DATABASE",
                "path_labels": ["input", "db.query"]
            }
        ]
        
        memory = GlobalMemory()
        new_findings = run_consistency_reconciliation(findings, processed_flows, memory, client, verbose=True)
        
        # verify both flows are now marked vulnerable in findings
        flow_ids = [f.get("flow_id") for f in new_findings]
        self.assertIn("flow-100", flow_ids)
        self.assertIn("flow-101", flow_ids)
        self.assertEqual(len(new_findings), 2)


if __name__ == "__main__":
    unittest.main()
