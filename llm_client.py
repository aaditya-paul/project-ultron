import os
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

CLOUD_PROVIDER_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "nvidia": "https://integrate.api.nvidia.com/v1",
}

CLOUD_PROVIDER_NAMES = {
    "groq": "Groq",
    "gemini": "Gemini",
    "nvidia": "NVIDIA",
}

def load_config():
    config_path = "ultron_config.json"
    defaults = {
        "llm_url": "http://localhost:11434",
        "llm_model": "gemma4:e2b",
        "temperature": 0.1,
        "max_tokens": 1024,
        "num_workers": 5,
        "timeout": 60.0,
        "verbose": False,
        "visualise": False,
        "version": "8.0.0",
        "model_overrides": {},
        "llm_mode": "local",
        "api_keys": {
            "groq": "",
            "gemini": "",
            "nvidia": ""
        },
        "cloud_chain": {
            "default": ["groq", "gemini", "nvidia"]
        },
        "cloud_models": {
            "groq": "llama-3.3-70b-versatile",
            "gemini": "gemini-2.0-flash",
            "nvidia": "meta/llama-3.1-8b-instruct"
        }
    }
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                for k, v in user_config.items():
                    if k in ("model_overrides", "api_keys", "cloud_chain", "cloud_models") and isinstance(v, dict):
                        defaults.setdefault(k, {}).update(v)
                    else:
                        defaults[k] = v
        except Exception:
            pass
    return defaults

def create_llm_client(part=None):
    config = load_config()
    mode = os.environ.get("ULTRON_LLM_MODE") or config.get("llm_mode", "local")
    if mode == "cloud":
        return CloudLLMClient(part=part)
    return LocalLLMClient(part=part)

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
        self.timeout = None  # local LLMs are unpredictable — wait as long as needed
        self.detected_api_type = None

    def _detect_api(self) -> str:
        if self.detected_api_type:
            return self.detected_api_type

        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    self.detected_api_type = "ollama"
                    return "ollama"
        except Exception:
            pass

        try:
            req = urllib.request.Request(f"{self.base_url}/health")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    self.detected_api_type = "llamacpp"
                    return "llamacpp"
        except Exception:
            pass

        if "11434" in self.base_url:
            self.detected_api_type = "ollama"
        elif "8080" in self.base_url:
            self.detected_api_type = "llamacpp"
        else:
            self.detected_api_type = "openai"

        return self.detected_api_type

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(self.base_url)
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                return resp.status in (200, 404, 403)
        except Exception:
            return False

    def is_model_available(self) -> bool:
        api_type = self._detect_api()
        if api_type != "ollama":
            return True

        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]

                target = self.model.lower()
                for m in models:
                    m_low = m.lower()
                    if m_low == target or m_low.startswith(target + ":") or target.startswith(m_low + ":"):
                        return True
                return False
        except Exception:
            return False

    def _build_body(self, api_type, prompt, max_tokens, stream=False):
        tokens = max_tokens or self.max_tokens
        if api_type == "ollama":
            return {
                "model": self.model,
                "prompt": prompt,
                "stream": stream,
                "options": {
                    "num_predict": tokens,
                    "temperature": self.temperature
                }
            }
        elif api_type == "llamacpp":
            return {
                "prompt": prompt,
                "n_predict": tokens,
                "temperature": self.temperature,
                "stream": stream
            }
        else:
            return {
                "model": self.model,
                "prompt": prompt,
                "max_tokens": tokens,
                "temperature": self.temperature,
                "stream": stream
            }

    def _stream_complete(self, prompt: str, max_tokens=None) -> str:
        api_type = self._detect_api()
        tokens = max_tokens or self.max_tokens

        if api_type == "ollama":
            url = f"{self.base_url}/api/generate"
        elif api_type == "llamacpp":
            url = f"{self.base_url}/completion"
        else:
            url = f"{self.base_url}/v1/completions"

        body = self._build_body(api_type, prompt, tokens, stream=True)

        from colors import GRN, RST

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            full_text = ""
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                for line_bytes in resp:
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    chunk = ""
                    done = False

                    if api_type == "ollama":
                        if line.startswith("{"):
                            try:
                                data = json.loads(line)
                                chunk = data.get("response", "")
                                done = data.get("done", False)
                            except json.JSONDecodeError:
                                pass
                    elif api_type == "llamacpp":
                        if line.startswith("data: "):
                            payload = line[6:].strip()
                            if payload == "[DONE]":
                                done = True
                            elif payload:
                                try:
                                    data = json.loads(payload)
                                    chunk = data.get("content", "")
                                    done = data.get("stop", False)
                                except json.JSONDecodeError:
                                    pass
                    else:
                        if line.startswith("data: "):
                            payload = line[6:].strip()
                            if payload == "[DONE]":
                                done = True
                            elif payload:
                                try:
                                    data = json.loads(payload)
                                    choices = data.get("choices", [])
                                    if choices:
                                        delta = choices[0].get("delta", {})
                                        chunk = delta.get("text", "") or delta.get("content", "")
                                except json.JSONDecodeError:
                                    pass

                    if chunk:
                        full_text += chunk
                        print(f"{GRN}{chunk}{RST}", end="", flush=True)
                    if done:
                        break
            print()
            return full_text.strip()
        except Exception as e:
            if os.environ.get("ULTRON_DEBUG") == "1":
                try:
                    from colors import RED, RST
                    print(f"  {RED}[DEBUG] LLM stream failed: {e}{RST}")
                except Exception:
                    print(f"  [DEBUG] LLM stream failed: {e}")
            return ""

    def complete(self, prompt: str, max_tokens=None, stream=False) -> str:
        if stream and os.environ.get("ULTRON_DEBUG") == "1":
            return self._stream_complete(prompt, max_tokens)

        api_type = self._detect_api()
        tokens = max_tokens or self.max_tokens

        if api_type == "ollama":
            url = f"{self.base_url}/api/generate"
        elif api_type == "llamacpp":
            url = f"{self.base_url}/completion"
        else:
            url = f"{self.base_url}/v1/completions"

        body = self._build_body(api_type, prompt, tokens, stream=False)

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
                try:
                    from colors import RED, RST
                    print(f"  {RED}[DEBUG] LLM connection failed: {e}{RST}")
                except Exception:
                    print(f"  [DEBUG] LLM connection failed: {e}")
            return ""

    def batch_complete(self, prompts: list[str], max_tokens=None) -> list[str]:
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            futures = [executor.submit(self.complete, p, max_tokens) for p in prompts]
            return [f.result() for f in futures]


class CloudLLMClient:
    def __init__(self, part=None):
        config = load_config()
        self.temperature = config["temperature"]
        self.max_tokens = config["max_tokens"]
        self.num_workers = config["num_workers"]
        self.timeout = config["timeout"]
        self.part = part or "default"
        self.api_keys = config.get("api_keys", {})
        self.cloud_chain = config.get("cloud_chain", {"default": ["groq", "gemini", "nvidia"]})
        self.cloud_models = config.get("cloud_models", {})
        self.model = self._resolve_model()

    def _resolve_model(self):
        chain = self._get_chain()
        if not chain:
            return "unknown"
        first = chain[0]
        return self.cloud_models.get(first, first)

    def _get_chain(self):
        raw = self.cloud_chain.get(self.part) or self.cloud_chain.get("default", ["groq", "gemini", "nvidia"])
        available = [p for p in raw if p in self.api_keys and self.api_keys.get(p)]
        if os.environ.get("ULTRON_DEBUG") == "1":
            missing = [p for p in raw if p not in available]
            if missing:
                from colors import YLW, RST
                names = [CLOUD_PROVIDER_NAMES.get(p, p) for p in missing]
                print(f"  {YLW}[!]{RST} cloud providers skipped (no key set): {', '.join(names)}")
        return available

    def is_available(self) -> bool:
        return len(self._get_chain()) > 0

    def is_model_available(self) -> bool:
        return self.is_available()

    def _call_provider(self, provider, prompt, max_tokens, stream=False):
        base = CLOUD_PROVIDER_URLS.get(provider)
        if not base:
            return ""
        url = f"{base}/chat/completions"
        api_key = self.api_keys.get(provider)
        if not api_key:
            return ""

        tokens = max_tokens or self.max_tokens
        model = self.cloud_models.get(provider, provider)

        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": tokens,
            "temperature": self.temperature,
            "stream": stream
        }

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Ultron/8.0",
            "Authorization": f"Bearer {api_key}"
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers
        )

        if stream and os.environ.get("ULTRON_DEBUG") == "1":
            return self._stream_provider(req)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                choices = res_data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip()
                return ""
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:200]
            if os.environ.get("ULTRON_DEBUG") == "1":
                from colors import RED, RST
                print(f"  {RED}[DEBUG] {CLOUD_PROVIDER_NAMES.get(provider, provider)} HTTP {e.code}: {err_body}{RST}")
            return ""
        except Exception as e:
            if os.environ.get("ULTRON_DEBUG") == "1":
                from colors import RED, RST
                print(f"  {RED}[DEBUG] {CLOUD_PROVIDER_NAMES.get(provider, provider)} error: {e}{RST}")
            return ""

    def _stream_provider(self, req):
        from colors import GRN, RST
        full_text = ""
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                for line_bytes in resp:
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    if line.startswith("data: "):
                        payload = line[6:].strip()
                        if payload == "[DONE]":
                            break
                        try:
                            data = json.loads(payload)
                            choices = data.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                chunk = delta.get("content", "")
                                if chunk:
                                    full_text += chunk
                                    print(f"{GRN}{chunk}{RST}", end="", flush=True)
                        except json.JSONDecodeError:
                            pass
            print()
            return full_text.strip()
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:200]
            if os.environ.get("ULTRON_DEBUG") == "1":
                from colors import RED, RST
                print(f"  {RED}[DEBUG] cloud stream HTTP {e.code}: {err_body}{RST}")
            return ""
        except Exception as e:
            if os.environ.get("ULTRON_DEBUG") == "1":
                from colors import RED, RST
                print(f"  {RED}[DEBUG] cloud stream failed: {e}{RST}")
            return ""

    def complete(self, prompt: str, max_tokens=None, stream=False) -> str:
        chain = self._get_chain()
        if not chain:
            if os.environ.get("ULTRON_DEBUG") == "1":
                from colors import RED, RST
                print(f"  {RED}[DEBUG] no cloud providers configured (set api_keys in config){RST}")
            return ""

        if os.environ.get("ULTRON_DEBUG") == "1":
            from colors import DIM, RST
            names = [CLOUD_PROVIDER_NAMES.get(p, p) for p in chain]
            print(f"  {DIM}[*] cloud fallback chain: {' -> '.join(names)}{RST}")

        errors = []
        for i, provider in enumerate(chain):
            result = self._call_provider(provider, prompt, max_tokens, stream)
            if result:
                return result
            msg = f"{CLOUD_PROVIDER_NAMES.get(provider, provider)} returned empty"
            errors.append(msg)
            has_next = i + 1 < len(chain)
            if os.environ.get("ULTRON_DEBUG") == "1":
                from colors import RED, YLW, RST
                label = f"{RED}FAIL{RST} {CLOUD_PROVIDER_NAMES.get(provider, provider)}"
                suffix = f"{YLW}falling back...{RST}" if has_next else f"{RED}no more providers{RST}"
                print(f"  {label} {suffix}")

        if os.environ.get("ULTRON_DEBUG") == "1":
            from colors import RED, RST
            for err in errors:
                print(f"    {RED}->{RST} {err}")
        return ""

    def batch_complete(self, prompts: list[str], max_tokens=None) -> list[str]:
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            futures = [executor.submit(self.complete, p, max_tokens) for p in prompts]
            return [f.result() for f in futures]
