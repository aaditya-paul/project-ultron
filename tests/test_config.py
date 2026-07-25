import unittest
import sys
import os
import tempfile
import json

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from llm_client import load_config, LocalLLMClient

class TestConfig(unittest.TestCase):
    def test_load_config_defaults(self):
        # Verify the structure of the default configuration
        config = load_config()
        self.assertIn("llm_url", config)
        self.assertIn("llm_model", config)
        self.assertIn("temperature", config)
        self.assertIn("max_tokens", config)
        self.assertIn("timeout", config)
        self.assertIn("version", config)
        self.assertIn("verbose", config)
        self.assertIn("visualise", config)
        self.assertIn("model_overrides", config)
        
        # Verify model_overrides exists and has parts
        overrides = config["model_overrides"]
        self.assertIn("classifier", overrides)
        self.assertIn("detector", overrides)
        self.assertIn("exploiter", overrides)
        self.assertIn("reporter", overrides)

    def test_local_llm_client_overrides(self):
        # Test that LocalLLMClient correctly resolves model overrides for parts
        # If no overrides, it defaults to config["llm_model"] or default
        client = LocalLLMClient(part="classifier")
        config = load_config()
        expected = config["model_overrides"].get("classifier", config["llm_model"])
        self.assertEqual(client.model, expected)

if __name__ == "__main__":
    unittest.main()
