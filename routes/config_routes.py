"""Configuration management routes — get, set, reset config values.

Each function is a standalone callable that returns structured dicts,
making them directly usable as MCP tools without an HTTP layer.
"""

import os
import json

from llm_client import load_config as _load_config


CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ultron_config.json")

VALID_PARTS = {"classifier", "detector", "exploiter", "reporter", "default"}
VALID_SETTINGS = {"verbose", "visualise", "temperature", "max_tokens", "timeout",
                  "num_workers", "llm_url", "llm_mode", "use_llm", "enable_cache", "cache_only"}

DEFAULT_CONFIG = {
    "llm_url": "http://localhost:11434",
    "llm_model": "qwen2.5-coder:3b",
    "temperature": 0.1,
    "max_tokens": 1024,
    "num_workers": 5,
    "timeout": 60.0,
    "version": "8.0.0",
    "verbose": False,
    "llm_mode": "local",
    "visualise": False,
    "use_llm": True,
    "model_overrides": {
        "classifier": "qwen2.5-coder:3b",
        "detector": "qwen2.5-coder:3b",
        "exploiter": "qwen2.5-coder:3b",
        "reporter": "qwen2.5-coder:3b"
    },
    "api_keys": {"groq": "", "gemini": "", "nvidia": ""},
    "cloud_chain": {"default": ["groq", "gemini", "nvidia"]},
    "cloud_models": {
        "groq": "llama-3.3-70b-versatile",
        "gemini": "gemini-2.0-flash",
        "nvidia": "meta/llama-3.1-8b-instruct"
    },
    "rate_limits": {},
    "enable_cache": True,
    "cache_only": False,
}


def get_config():
    """Show full current configuration.

    MCP tool candidate: ultron_get_config

    Returns:
        dict with all configuration values
    """
    config = _load_config()
    api_keys = config.get("api_keys", {})
    configured_keys = [k for k, v in api_keys.items() if v]

    return {
        "llm_mode": config.get("llm_mode", "local"),
        "llm_url": config.get("llm_url"),
        "llm_model": config.get("llm_model"),
        "temperature": config.get("temperature"),
        "max_tokens": config.get("max_tokens"),
        "timeout": config.get("timeout"),
        "num_workers": config.get("num_workers"),
        "version": config.get("version"),
        "verbose": config.get("verbose", False),
        "visualise": config.get("visualise", False),
        "use_llm": config.get("use_llm", True),
        "enable_cache": config.get("enable_cache", True),
        "cache_only": config.get("cache_only", False),
        "model_overrides": config.get("model_overrides", {}),
        "api_keys_configured": configured_keys,
        "cloud_chain": config.get("cloud_chain", {}),
        "cloud_models": config.get("cloud_models", {}),
        "rate_limits": config.get("rate_limits", {}),
    }


def get_config_value(key):
    """Get a single configuration value.

    MCP tool candidate: ultron_get_config_value

    Args:
        key: Configuration key name

    Returns:
        dict with the key and its value
    """
    config = _load_config()
    if key not in config:
        valid = list(config.keys()) + list(config.get("model_overrides", {}).keys())
        return {"success": False, "error": f"Unknown key '{key}'. Valid keys: {', '.join(valid[:20])}"}

    return {"success": True, "key": key, "value": config[key]}


def set_config_value(key, value):
    """Set a configuration value.

    MCP tool candidate: ultron_set_config_value

    Args:
        key: Setting name (e.g. "verbose", "temperature", "llm_url")
        value: Value to set (string, will be coerced to correct type)

    Returns:
        dict with update result
    """
    config = _load_config()

    if key not in VALID_SETTINGS:
        return {
            "success": False,
            "error": f"Invalid setting '{key}'. Valid settings: {', '.join(sorted(VALID_SETTINGS))}",
        }

    if key == "verbose" or key == "visualise" or key == "use_llm" or key == "enable_cache" or key == "cache_only":
        if isinstance(value, str):
            val = value.lower() in ("true", "1", "yes", "on", "enable", "enabled")
        else:
            val = bool(value)
        config[key] = val

    elif key == "temperature" or key == "timeout":
        try:
            val = float(value) if isinstance(value, str) else float(value)
        except (ValueError, TypeError):
            return {"success": False, "error": f"Invalid float value for {key}: {value}"}
        config[key] = val

    elif key == "max_tokens" or key == "num_workers":
        try:
            val = int(value) if isinstance(value, str) else int(value)
        except (ValueError, TypeError):
            return {"success": False, "error": f"Invalid integer value for {key}: {value}"}
        config[key] = val

    elif key == "llm_mode":
        val = value.lower() if isinstance(value, str) else value
        if val not in ("local", "cloud"):
            return {"success": False, "error": f"Invalid llm_mode '{value}'. Use 'local' or 'cloud'."}
        config[key] = val

    elif key == "llm_url":
        config[key] = str(value)

    _save_config(config)
    return {"success": True, "key": key, "value": config[key], "message": f"Setting '{key}' updated to {config[key]}"}


def set_model_override(part, model):
    """Set a model override for a specific agent part.

    MCP tool candidate: ultron_set_model_override

    Args:
        part: Agent part ("classifier", "detector", "exploiter", "reporter", or "default")
        model: Model name string

    Returns:
        dict with update result
    """
    config = _load_config()

    part = part.lower()
    if part not in VALID_PARTS:
        return {
            "success": False,
            "error": f"Invalid part '{part}'. Valid parts: {', '.join(sorted(VALID_PARTS))}",
        }

    if part == "default":
        config["llm_model"] = model
        message = f"Default model updated to '{model}'"
    else:
        overrides = config.setdefault("model_overrides", {})
        overrides[part] = model
        message = f"Model override for '{part}' updated to '{model}'"

    _save_config(config)
    return {"success": True, "part": part, "model": model, "message": message}


def get_api_keys_status():
    """Check which API keys are configured.

    MCP tool candidate: ultron_get_api_keys_status

    Returns:
        dict with configured providers
    """
    config = _load_config()
    api_keys = config.get("api_keys", {})
    configured = {k: bool(v) for k, v in api_keys.items()}
    chain = config.get("cloud_chain", {}).get("default", [])
    models = config.get("cloud_models", {})

    providers = []
    for p in chain:
        providers.append({
            "name": p,
            "has_key": configured.get(p, False),
            "model": models.get(p, "default"),
            "url": _provider_url(p),
        })

    return {
        "providers": providers,
        "chain": chain,
        "any_configured": any(configured.get(p, False) for p in chain),
    }


def reset_config():
    """Reset configuration to factory defaults.

    MCP tool candidate: ultron_reset_config

    Returns:
        dict with reset result
    """
    try:
        _save_config(DEFAULT_CONFIG)
        return {"success": True, "message": "Configuration reset to defaults successfully."}
    except Exception as e:
        return {"success": False, "error": f"Failed to reset configuration: {e}"}


# ── Internal helpers ────────────────────────────────────────────────────────

def _save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def _provider_url(provider):
    urls = {
        "groq": "https://api.groq.com/openai/v1",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
        "nvidia": "https://integrate.api.nvidia.com/v1",
    }
    return urls.get(provider, "")
