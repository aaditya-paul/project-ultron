"""FastAPI HTTP server for Ultron operations.

Every endpoint wraps a pure route function from routes/ that can also
be used directly as an MCP tool or imported from Python code.

Run with:
    pip install fastapi uvicorn
    python -m routes.server

Or for development:
    uvicorn routes.server:app --reload
"""

import os
import sys

# Ensure parent directory is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except ImportError:
    raise ImportError(
        "FastAPI and Pydantic are required for the HTTP server.\n"
        "Install with: pip install fastapi uvicorn"
    )

from routes import (
    list_repos, clone_repo, scan_repo, delete_repo, delete_all_repos,
    get_repo_status, visualise_repo,
    get_config, get_config_value, set_config_value, reset_config,
    set_model_override, get_api_keys_status,
    run_detection, run_ast_parse, run_rules as run_rules_pipeline,
    run_llm_detection, run_full_analysis,
    get_findings, get_security_graph,
)

app = FastAPI(
    title="Ultron Security Analysis API",
    description="Multi-agent security analysis engine — clone, parse, taint, and detect vulnerabilities in source code.",
    version="8.0.0",
)


# ── Request/Response models ─────────────────────────────────────────────────

class CloneRequest(BaseModel):
    url: str
    pull_if_exists: bool = True


class ConfigSetRequest(BaseModel):
    key: str
    value: str | int | float | bool


class ModelOverrideRequest(BaseModel):
    part: str
    model: str


class ScanRequest(BaseModel):
    name: str


class DeleteRequest(BaseModel):
    name: str


# ── Repository management endpoints ─────────────────────────────────────────

@app.get("/api/repos")
def api_list_repos():
    """List all cloned repositories."""
    result = list_repos()
    return {"success": True, **result}


@app.post("/api/repos/clone")
def api_clone_repo(req: CloneRequest):
    """Clone a repository and run full analysis."""
    result = clone_repo(req.url, pull_if_exists=req.pull_if_exists)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Clone failed"))
    return {"success": True, **result}


@app.post("/api/repos/scan")
def api_scan_repo(req: ScanRequest):
    """Re-analyze a cloned repository."""
    result = scan_repo(req.name)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Not found"))
    return {"success": True, **result}


@app.get("/api/repos/{name}")
def api_repo_status(name: str):
    """Get detailed status of a cloned repository."""
    result = get_repo_status(name)
    if not result.get("exists"):
        raise HTTPException(status_code=404, detail=result.get("error", "Not found"))
    return {"success": True, **result}


@app.delete("/api/repos/{name}")
def api_delete_repo(name: str):
    """Delete a cloned repository and its workspace."""
    result = delete_repo(name)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Delete failed"))
    return {"success": True, **result}


@app.delete("/api/repos")
def api_delete_all():
    """Delete all cloned repositories and workspaces."""
    result = delete_all_repos()
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Delete failed"))
    return {"success": True, **result}


@app.post("/api/repos/{name}/visualise")
def api_visualise_repo(name: str):
    """Regenerate visualizations from cached AST."""
    result = visualise_repo(name)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Visualisation failed"))
    return {"success": True, **result}


# ── Analysis pipeline endpoints ─────────────────────────────────────────────

@app.post("/api/repos/{name}/analysis/detection")
def api_run_detection(name: str):
    """Detect languages and frameworks in a repository."""
    result = run_detection(name)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Not found"))
    return {"success": True, **result}


@app.post("/api/repos/{name}/analysis/ast")
def api_run_ast(name: str):
    """Parse AST for a repository."""
    result = run_ast_parse(name)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Not found"))
    return {"success": True, **result}


@app.post("/api/repos/{name}/analysis/rules")
def api_run_rules(name: str):
    """Run deterministic security rules."""
    result = run_rules_pipeline(name)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Not found"))
    return {"success": True, **result}


@app.post("/api/repos/{name}/analysis/llm")
def api_run_llm(name: str):
    """Run LLM-based vulnerability detection."""
    result = run_llm_detection(name)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "LLM detection failed"))
    return {"success": True, **result}


@app.post("/api/repos/{name}/analysis/full")
def api_run_full_analysis(name: str):
    """Run the complete analysis pipeline."""
    result = run_full_analysis(name)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Analysis failed"))
    return {"success": True, **result}


# ── Results endpoints ───────────────────────────────────────────────────────

@app.get("/api/repos/{name}/findings")
def api_get_findings(name: str):
    """Get cached findings from a previous scan."""
    result = get_findings(name)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Not found"))
    return {"success": True, **result}


@app.get("/api/repos/{name}/security-graph")
def api_get_security_graph(name: str):
    """Get cached security graph data."""
    result = get_security_graph(name)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Not found"))
    return {"success": True, **result}


# ── Configuration endpoints ─────────────────────────────────────────────────

@app.get("/api/config")
def api_get_config():
    """Show full current configuration."""
    return {"success": True, **get_config()}


@app.get("/api/config/{key}")
def api_get_config_value(key: str):
    """Get a single configuration value."""
    result = get_config_value(key)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Unknown key"))
    return {"success": True, **result}


@app.post("/api/config")
def api_set_config_value(req: ConfigSetRequest):
    """Set a configuration value."""
    result = set_config_value(req.key, req.value)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Invalid setting"))
    return {"success": True, **result}


@app.post("/api/config/model-override")
def api_set_model_override(req: ModelOverrideRequest):
    """Set a model override for an agent part."""
    result = set_model_override(req.part, req.model)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Invalid part"))
    return {"success": True, **result}


@app.get("/api/config/api-keys")
def api_get_api_keys():
    """Check which cloud API keys are configured."""
    return {"success": True, **get_api_keys_status()}


@app.post("/api/config/reset")
def api_reset_config():
    """Reset configuration to factory defaults."""
    result = reset_config()
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Reset failed"))
    return {"success": True, **result}


# ── Health check ────────────────────────────────────────────────────────────

@app.get("/api/health")
def api_health():
    """Health check endpoint."""
    return {
        "success": True,
        "status": "ok",
        "version": "8.0.0",
    }


# ── Main entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    on_render = "PORT" in os.environ
    host = os.environ.get("HOST", "0.0.0.0" if on_render else "127.0.0.1")
    port = int(os.environ["PORT"]) if on_render else 8742
    uvicorn.run(app, host=host, port=port)
