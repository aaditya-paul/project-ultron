import os
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

def load_config():
    config_path = "ultron_config.json"
    defaults = {
        "llm_url": "http://localhost:11434",
        "llm_model": "qwen2.5-coder:3b",
        "temperature": 0.1,
        "max_tokens": 100,
        "num_workers": 5,
        "timeout": 15.0,
        "verbose": False,
        "visualise": False,
        "version": "8.0.0",
        "model_overrides": {
            "classifier": "qwen2.5-coder:3b",
            "detector": "qwen2.5-coder:3b",
            "exploiter": "qwen2.5-coder:3b",
            "reporter": "qwen2.5-coder:3b"
        }
    }
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                for k, v in user_config.items():
                    if k == "model_overrides" and isinstance(v, dict):
                        defaults.setdefault("model_overrides", {}).update(v)
                    else:
                        defaults[k] = v
        except Exception:
            pass
    return defaults

class LocalLLMClient:
    def __init__(self, base_url=None, model=None, part=None):
        config = load_config()
        self.base_url = base_url or os.environ.get("ULTRON_LLM_URL") or config["llm_url"]
        
        override_model = None
        if part and "model_overrides" in config:
            override_model = config["model_overrides"].get(part)
            
        self.model = model or override_model or os.environ.get("ULTRON_LLM_MODEL") or config["llm_model"]
        self.temperature = config["temperature"]
        self.max_tokens = config["max_tokens"]
        self.num_workers = config["num_workers"]
        self.timeout = config["timeout"]
        self.detected_api_type = None

    def _detect_api(self) -> str:
        if self.detected_api_type:
            return self.detected_api_type
            
        # Try to contact base_url to detect the API type
        # 1. Try Ollama: check base_url/api/tags
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    self.detected_api_type = "ollama"
                    return "ollama"
        except Exception:
            pass
            
        # 2. Try llama.cpp: check base_url/health
        try:
            req = urllib.request.Request(f"{self.base_url}/health")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    self.detected_api_type = "llamacpp"
                    return "llamacpp"
        except Exception:
            pass
            
        # 3. Default fallback by URL / port
        if "11434" in self.base_url:
            self.detected_api_type = "ollama"
        elif "8080" in self.base_url:
            self.detected_api_type = "llamacpp"
        else:
            self.detected_api_type = "openai"
            
        return self.detected_api_type

    def is_available(self) -> bool:
        try:
            # Short timeout to avoid blocking CLI
            req = urllib.request.Request(self.base_url)
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                return resp.status in (200, 404, 403)
        except Exception:
            return False

    def is_model_available(self) -> bool:
        api_type = self._detect_api()
        if api_type != "ollama":
            # Non-Ollama servers (e.g. llama.cpp) generally run one hardcoded model directly
            return True
            
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                
                target = self.model.lower()
                for m in models:
                    m_low = m.lower()
                    # Match exact tag, or with default :latest tags
                    if m_low == target or m_low.startswith(target + ":") or target.startswith(m_low + ":"):
                        return True
                return False
        except Exception:
            return False

    def complete(self, prompt: str, max_tokens=None) -> str:
        api_type = self._detect_api()
        tokens = max_tokens or self.max_tokens
        
        if api_type == "ollama":
            url = f"{self.base_url}/api/generate"
            body = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": tokens,
                    "temperature": self.temperature
                }
            }
        elif api_type == "llamacpp":
            url = f"{self.base_url}/completion"
            body = {
                "prompt": prompt,
                "n_predict": tokens,
                "temperature": self.temperature
            }
        else: # openai compatible
            url = f"{self.base_url}/v1/completions"
            body = {
                "model": self.model,
                "prompt": prompt,
                "max_tokens": tokens,
                "temperature": self.temperature
            }
            
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                
                if api_type == "ollama":
                    return res_data.get("response", "").strip()
                elif api_type == "llamacpp":
                    return res_data.get("content", "").strip()
                else:
                    choices = res_data.get("choices", [])
                    if choices:
                        return choices[0].get("text", "").strip()
                    return ""
        except Exception as e:
            if os.environ.get("ULTRON_DEBUG") == "1":
                # import local colors to avoid circular imports or missing definitions
                try:
                    from colors import RED, RST
                    print(f"  {RED}[DEBUG] LLM connection failed: {e}{RST}")
                except Exception:
                    print(f"  [DEBUG] LLM connection failed: {e}")
            return ""

    def batch_complete(self, prompts: list[str], max_tokens=None) -> list[str]:
        # Process concurrent completions utilizing config's num_workers
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            futures = [executor.submit(self.complete, p, max_tokens) for p in prompts]
            return [f.result() for f in futures]
