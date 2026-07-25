from dataclasses import dataclass, asdict
import os

@dataclass
class FunctionFeatures:
    # Identity
    name: str
    file_path: str
    line: int
    language: str
    
    # Signature
    params: list[str]
    param_count: int
    
    # Body analysis (from parser)
    body_text: str                     # truncated source (~1000 chars)
    calls_made: list[str]             # e.g., ["db.users.create", "logger.info"]
    assignments: list[dict]           # [{"target": "result", "value": "db.users.create(...)"}]
    returns: list[str]                # ["result"]
    field_accesses: list[str]         # ["payload.email", "payload.name"]
    
    # Context
    file_imports: list[str]           # ["prisma", "express", "bcrypt"]
    calls_to_this: list[str]          # function IDs that call this one
    called_by_this: list[str]         # function IDs this one calls
    
    # Structural hints
    is_exported: bool
    is_async: bool
    is_in_route_file: bool            # file path heuristic
    has_error_handling: bool           # try/catch around calls

def extract_features(ast_data) -> list[FunctionFeatures]:
    if not ast_data or "files" not in ast_data:
        return []
        
    features_list = []
    
    # Map function name to list of (file_path, name) to resolve calls
    func_name_map = {}
    for fpath, info in ast_data["files"].items():
        for fn in info.get("functions", []):
            if fn.get("anonymous", False) or not fn.get("name"):
                continue
            name = fn["name"]
            func_name_map.setdefault(name.lower(), []).append((fpath, name))
            
    def resolve_call_target(call_name):
        c_low = call_name.lower().strip()
        candidates = func_name_map.get(c_low, [])
        if candidates:
            fpath, name = candidates[0]
            return f"fn:{fpath}::{name}"
        return None

    calls_to = {}
    called_by = {}
    
    for fpath, info in ast_data["files"].items():
        for fn in info.get("functions", []):
            fn_id = f"fn:{fpath}::{fn.get('name', 'anonymous')}"
            calls_to[fn_id] = set()
            called_by[fn_id] = set()

    for fpath, info in ast_data["files"].items():
        functions = info.get("functions", [])
        calls = info.get("calls", [])
        
        for fn in functions:
            fn_name = fn.get("name", "anonymous")
            fn_id = f"fn:{fpath}::{fn_name}"
            start = fn["line"]
            end = fn.get("end_line", start)
            
            for call in calls:
                call_text = call["text"] if isinstance(call, dict) else call
                call_line = call.get("line", 0) if isinstance(call, dict) else 0
                
                if start <= call_line <= end:
                    if "(" in call_text:
                        call_name = call_text.split("(")[0].strip().split(".")[-1].split()[-1]
                    else:
                        call_name = call_text.strip().split(".")[-1]
                    
                    if not call_name or call_name in ("if", "for", "while", "return", "import", "from", "pass", "def", "class", "const", "let", "var", "function"):
                        continue
                        
                    target_id = resolve_call_target(call_name)
                    if target_id and target_id != fn_id:
                        called_by.setdefault(fn_id, set()).add(target_id)
                        calls_to.setdefault(target_id, set()).add(fn_id)

    for fpath, info in ast_data["files"].items():
        imports = info.get("imports", [])
        functions = info.get("functions", [])
        assignments = info.get("assignments", [])
        returns = info.get("returns", [])
        field_accesses = info.get("field_accesses", [])
        calls = info.get("calls", [])
        
        for fn in functions:
            fn_name = fn.get("name", "anonymous")
            fn_id = f"fn:{fpath}::{fn_name}"
            start = fn["line"]
            end = fn.get("end_line", start)
            
            fn_assigns = [
                {"target": a["target"], "value": a["value_text"]}
                for a in assignments
                if start <= a["line"] <= end
            ]
            fn_returns = [
                r["value_text"]
                for r in returns
                if start <= r["line"] <= end
            ]
            fn_fields = [
                fa["full_text"]
                for fa in field_accesses
                if start <= fa["line"] <= end
            ]
            fn_calls = [
                c["text"]
                for c in calls
                if start <= c["line"] <= end
            ]
            
            body = fn.get("body_text", "")
            
            is_exported = False
            if not fn_name.startswith("_") and fn_name != "anonymous":
                is_exported = True
            
            is_async = "async" in body.lower()
            
            is_in_route = False
            path_lower = fpath.lower()
            route_indicators = ("/routes/", "/api/", "/controllers/", "/middleware/", "route.", "api.", "controller.")
            if any(ind in path_lower for ind in route_indicators):
                is_in_route = True
                
            has_error = any(kw in body.lower() for kw in ("try", "catch", "except", "throw", "raise"))
            
            feat = FunctionFeatures(
                name=fn_name,
                file_path=fpath,
                line=start,
                language=info.get("language", ""),
                params=fn.get("params", []),
                param_count=len(fn.get("params", [])),
                body_text=body,
                calls_made=fn_calls,
                assignments=fn_assigns,
                returns=fn_returns,
                field_accesses=fn_fields,
                file_imports=imports,
                calls_to_this=sorted(list(calls_to.get(fn_id, set()))),
                called_by_this=sorted(list(called_by.get(fn_id, set()))),
                is_exported=is_exported,
                is_async=is_async,
                is_in_route_file=is_in_route,
                has_error_handling=has_error
            )
            features_list.append(feat)
            
    return features_list
