import os
import json

from colors import DIM, WHT, CYAN, GRN, YLW, RST

LANGUAGE_PARSERS = {}

def _init_parsers():
    if LANGUAGE_PARSERS:
        return
    try:
        from tree_sitter import Language, Parser

        configs = [
            ("Python",     "tree_sitter_python",     "language"),
            ("JavaScript", "tree_sitter_javascript", "language"),
            ("TypeScript", "tree_sitter_typescript", "language_typescript"),
            ("TSX",        "tree_sitter_typescript", "language_tsx"),
            ("Go",         "tree_sitter_go",         None),
            ("Rust",       "tree_sitter_rust",       None),
            ("Java",       "tree_sitter_java",       None),
            ("C#",         "tree_sitter_c_sharp",    None),
            ("PHP",        "tree_sitter_php",        "language_php"),
            ("Ruby",       "tree_sitter_ruby",       "language"),
            ("Kotlin",     "tree_sitter_kotlin",     "language"),
            ("Swift",      "tree_sitter_swift",      "language"),
        ]

        cpp_parser = None
        for lang_name, mod_name, func_name in configs:
            try:
                mod = __import__(mod_name)
                fn = getattr(mod, func_name) if func_name else mod.language
                lang = Language(fn())
                parser = Parser(lang)
                if mod_name == "tree_sitter_cpp" and cpp_parser is None:
                    cpp_parser = parser
                LANGUAGE_PARSERS[lang_name] = parser
            except Exception:
                pass

        if cpp_parser:
            LANGUAGE_PARSERS["C"] = cpp_parser
            LANGUAGE_PARSERS["C++"] = cpp_parser

    except ImportError:
        pass

EXTENSION_LANG = {}

def _init_ext_map():
    if EXTENSION_LANG:
        return
    try:
        from tree_sitter import Language, Parser

        mapping = {
            ".py":    "Python",
            ".js":    "JavaScript",
            ".jsx":   "JavaScript",
            ".ts":    "TypeScript",
            ".tsx":   "TSX",
            ".go":    "Go",
            ".rs":    "Rust",
            ".java":  "Java",
            ".cs":    "C#",
            ".c":     "C",
            ".cpp":   "C++",
            ".cc":    "C++",
            ".h":     "C++",
            ".hpp":   "C++",
            ".php":   "PHP",
            ".rb":    "Ruby",
            ".kt":    "Kotlin",
            ".swift": "Swift",
        }
        for ext, lang in mapping.items():
            EXTENSION_LANG[ext] = lang
    except ImportError:
        pass

NODE_EXTRACT = {
    "Python": {
        "function":   "function_definition",
        "class":      "class_definition",
        "import":     ("import_statement", "import_from_statement"),
        "call":       "call",
        "assignment": ("assignment", "augmented_assignment"),
        "return":     "return_statement",
        "field_access": "attribute",
    },
    "JavaScript": {
        "function":   ("function_declaration", "arrow_function", "method_definition"),
        "class":      "class_declaration",
        "import":     ("import_statement", "import_expression"),
        "call":       "call_expression",
        "assignment": ("assignment_expression", "variable_declarator"),
        "return":     "return_statement",
        "field_access": "member_expression",
    },
    "TypeScript": {
        "function":   ("function_declaration", "arrow_function", "method_definition"),
        "class":      "class_declaration",
        "import":     ("import_statement", "import_expression"),
        "call":       "call_expression",
        "assignment": ("assignment_expression", "variable_declarator"),
        "return":     "return_statement",
        "field_access": "member_expression",
    },
    "TSX": {
        "function":   ("function_declaration", "arrow_function", "method_definition"),
        "class":      "class_declaration",
        "import":     ("import_statement", "import_expression"),
        "call":       "call_expression",
        "assignment": ("assignment_expression", "variable_declarator"),
        "return":     "return_statement",
        "field_access": "member_expression",
    },
    "Go": {
        "function":   "function_declaration",
        "class":      "type_declaration",
        "import":     "import_declaration",
        "call":       "call_expression",
        "assignment": ("assignment_statement", "short_var_declaration", "var_spec"),
        "return":     "return_statement",
        "field_access": "selector_expression",
    },
    "Rust": {
        "function":   "function_item",
        "class":      "struct_item",
        "import":     "use_declaration",
        "call":       "call_expression",
        "assignment": ("let_declaration", "assignment_expression"),
        "return":     "return_expression",
        "field_access": "field_expression",
    },
    "Java": {
        "function":   "method_declaration",
        "class":      "class_declaration",
        "import":     "import_declaration",
        "call":       "method_invocation",
        "assignment": ("assignment_expression", "variable_declarator"),
        "return":     "return_statement",
        "field_access": "field_access",
    },
    "C#": {
        "function":   ("method_declaration", "local_function_statement"),
        "class":      "class_declaration",
        "import":     "using_directive",
        "call":       "invocation_expression",
        "assignment": ("assignment_expression", "variable_declarator"),
        "return":     "return_statement",
        "field_access": "member_access_expression",
    },
    "C": {
        "function":   ("function_definition", "declaration"),
        "class":      "struct_specifier",
        "import":     ("preproc_include", "include_next"),
        "call":       "call_expression",
        "assignment": ("assignment_expression", "init_declarator"),
        "return":     "return_statement",
        "field_access": ("field_expression", "member_expression"),
    },
    "C++": {
        "function":   ("function_definition", "declaration"),
        "class":      ("class_specifier", "struct_specifier"),
        "import":     ("preproc_include", "include_next"),
        "call":       "call_expression",
        "assignment": ("assignment_expression", "init_declarator"),
        "return":     "return_statement",
        "field_access": ("field_expression", "member_expression"),
    },
    "PHP": {
        "function":   "function_definition",
        "class":      "class_declaration",
        "import":     ("include_expression", "require_expression"),
        "call":       "function_call_expression",
        "assignment": "assignment_expression",
        "return":     "return_statement",
        "field_access": ("member_access_expression", "property_access_expression"),
    },
    "Ruby": {
        "function":   ("method", "singleton_method"),
        "class":      "class",
        "import":     "require",
        "call":       "call",
        "assignment": ("assignment", "operator_assignment"),
        "return":     "return",
        "field_access": ("call", "attribute"),
    },
    "Kotlin": {
        "function":   ("function_declaration", "named_function"),
        "class":      "class_declaration",
        "import":     "import_header",
        "call":       "call_expression",
        "assignment": ("assignment", "property"),
        "return":     ("return", "return_expression"),
        "field_access": "navigation_expression",
    },
    "Swift": {
        "function":   "function_declaration",
        "class":      "class_declaration",
        "import":     "import_declaration",
        "call":       "call_expression",
        "assignment": ("assignment_expression", "pattern_binding"),
        "return":     "return_statement",
        "field_access": ("navigation_expression", "navigation_suffix", "member_access_expression"),
    },
}

def _find_children(node, node_type_set, depth=0, max_depth=50):
    if depth > max_depth:
        return []
    results = []
    if node.type in node_type_set:
        results.append(node)
    for child in node.named_children:
        results.extend(_find_children(child, node_type_set, depth + 1, max_depth))
    return results

def _node_text(node, source_bytes):
    try:
        return node.text.decode("utf-8", errors="replace")
    except Exception:
        return ""

def _extract_name(node, source_bytes):
    for child in node.named_children:
        if child.type == "identifier":
            return _node_text(child, source_bytes), False
        if child.type in ("property_identifier", "field_identifier"):
            return _node_text(child, source_bytes), False
    return None, True

def _extract_params(node, source_bytes):
    for child in node.named_children:
        if child.type == "parameters":
            return [
                _node_text(p, source_bytes)
                for p in child.named_children
                if p.type == "identifier"
            ]
        if child.type == "formal_parameters":
            params = []
            for p in child.named_children:
                ptxt = _node_text(p, source_bytes)
                if ptxt and ptxt != ",":
                    params.append(ptxt)
            return params
    return []

def _extract_import_text(node, source_bytes):
    return _node_text(node, source_bytes).strip()

def _extract_assignment(node, source_bytes):
    target_node = None
    value_node = None
    # Try child by field names
    for t_field in ["left", "id", "pattern", "name", "variable"]:
        t = node.child_by_field_name(t_field)
        if t:
            target_node = t
            break
    for v_field in ["right", "init", "value"]:
        v = node.child_by_field_name(v_field)
        if v:
            value_node = v
            break
    
    # Fallback to children parsing
    if not target_node or not value_node:
        named_children = node.named_children
        if len(named_children) >= 2:
            if not target_node:
                target_node = named_children[0]
            if not value_node:
                value_node = named_children[-1]
    
    target_text = _node_text(target_node, source_bytes).strip() if target_node else ""
    value_text = _node_text(value_node, source_bytes).strip() if value_node else ""
    
    # If still empty, use a fallback: if node text contains '=', split it
    if not target_text and not value_text:
        full_text = _node_text(node, source_bytes)
        if "=" in full_text:
            parts = full_text.split("=", 1)
            target_text = parts[0].strip()
            value_text = parts[1].strip()
        else:
            target_text = full_text.strip()
            value_text = ""
    return target_text, value_text

def _extract_return(node, source_bytes):
    val_node = node.child_by_field_name("value") or node.child_by_field_name("expression")
    if not val_node and node.named_children:
        val_node = node.named_children[-1]
    
    if val_node:
        return _node_text(val_node, source_bytes).strip()
    else:
        txt = _node_text(node, source_bytes).strip()
        if txt.startswith("return "):
            return txt[7:].strip()
        elif txt.startswith("return"):
            return txt[6:].strip()
        return txt

def _extract_field_access(node, source_bytes):
    return _node_text(node, source_bytes).strip()

def parse_file(filepath, lang_name):
    _init_parsers()
    if lang_name not in LANGUAGE_PARSERS:
        return None

    try:
        with open(filepath, "rb") as f:
            source = f.read()
    except Exception:
        return None

    parser = LANGUAGE_PARSERS[lang_name]
    try:
        tree = parser.parse(source)
    except Exception:
        return None

    root = tree.root_node
    node_types = NODE_EXTRACT.get(lang_name, {})
    func_types = node_types.get("function", ())
    class_types = node_types.get("class", ())
    import_types = node_types.get("import", ())
    call_types = node_types.get("call", ())
    assign_types = node_types.get("assignment", ())
    return_types = node_types.get("return", ())
    field_types = node_types.get("field_access", ())

    if isinstance(func_types, str):
        func_types = (func_types,)
    if isinstance(class_types, str):
        class_types = (class_types,)
    if isinstance(import_types, str):
        import_types = (import_types,)
    if isinstance(call_types, str):
        call_types = (call_types,)
    if isinstance(assign_types, str):
        assign_types = (assign_types,)
    if isinstance(return_types, str):
        return_types = (return_types,)
    if isinstance(field_types, str):
        field_types = (field_types,)

    func_set = set(func_types)
    class_set = set(class_types)
    import_set = set(import_types)
    call_set = set(call_types)
    assign_set = set(assign_types)
    return_set = set(return_types)
    field_set = set(field_types)

    result = {
        "language": lang_name,
        "functions": [],
        "classes": [],
        "imports": [],
        "calls": [],
        "assignments": [],
        "returns": [],
        "field_accesses": [],
    }

    for node in _find_children(root, func_set):
        name, is_anon = _extract_name(node, source)
        params = _extract_params(node, source)
        
        body_text = _node_text(node, source)
        if len(body_text) > 1000:
            body_text = body_text[:1000] + "... [TRUNCATED]"
            
        result["functions"].append({
            "name": name or "",
            "params": params,
            "line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "anonymous": is_anon,
            "body_text": body_text,
        })

    for node in _find_children(root, class_set):
        name = _extract_name(node, source)[0] or ""
        result["classes"].append({
            "name": name,
            "line": node.start_point[0] + 1,
        })

    for node in _find_children(root, import_set):
        text = _extract_import_text(node, source)
        if text:
            result["imports"].append(text)

    for node in _find_children(root, call_set):
        text = _node_text(node, source)[:80]
        if text:
            result["calls"].append({
                "text": text,
                "line": node.start_point[0] + 1,
            })

    for node in _find_children(root, assign_set):
        target, val_txt = _extract_assignment(node, source)
        result["assignments"].append({
            "target": target,
            "value_text": val_txt,
            "line": node.start_point[0] + 1,
        })

    for node in _find_children(root, return_set):
        val_txt = _extract_return(node, source)
        result["returns"].append({
            "value_text": val_txt,
            "line": node.start_point[0] + 1,
        })

    for node in _find_children(root, field_set):
        full_txt = _extract_field_access(node, source)
        result["field_accesses"].append({
            "full_text": full_txt,
            "line": node.start_point[0] + 1,
        })

    return result

def classify_file_role(relpath: str) -> str:
    path_lower = relpath.replace("\\", "/").lower()
    filename = os.path.basename(path_lower)
    
    if any(p in path_lower for p in ("/node_modules/", "/vendor/", "/assets/private/", "/dist/", "/build/output/")):
        return "VENDOR"
    if filename.endswith((".min.js", ".min.css", ".bundle.js")):
        return "VENDOR"
        
    if any(p in path_lower for p in ("/cypress/", "/test/", "/tests/", "/__tests__/", "/spec/", "/specs/")):
        return "TEST"
    if any(fn in filename for fn in (".spec.", ".test.", "cypress.config", "jest.config", "playwright.config", "vitest.config")):
        return "TEST"

    if any(p in path_lower for p in ("/codefixes/", "/data/static/", "/static/codefixes/", "/fixtures/")):
        return "FIXTURE"
        
    if filename in ("gruntfile.js", "gulpfile.js", "webpack.config.js", "vite.config.js", "vite.config.ts", "rollup.config.js", "next.config.js", "next.config.mjs"):
        return "BUILD"

    if any(p in path_lower for p in ("/frontend/", "/client/", "/src/app/", "/public/")):
        return "RUNTIME_CLIENT"
        
    return "RUNTIME"


def parse_repo(repo_path):
    _init_parsers()
    _init_ext_map()

    if not LANGUAGE_PARSERS:
        print(f"  {YLW}[!]{RST} tree-sitter not available. install with: pip install tree-sitter tree-sitter-python ...")
        return None

    files_data = {}
    total = 0
    failed = 0

    for dirpath, dirnames, filenames in os.walk(repo_path):
        depth = dirpath.replace(repo_path, "").count(os.sep)
        if depth > 5:
            continue

        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".idea", ".vscode")]

        basename = os.path.basename(dirpath)
        if basename == ".git":
            continue
        for f in filenames:
            ext = os.path.splitext(f)[1].lower()
            lang = EXTENSION_LANG.get(ext)
            if not lang:
                continue
            filepath = os.path.join(dirpath, f)
            relpath = os.path.relpath(filepath, repo_path)
            parsed = parse_file(filepath, lang)
            if parsed:
                parsed["file_role"] = classify_file_role(relpath)
                files_data[relpath] = parsed
                total += 1
            else:
                failed += 1

    return {
        "files": files_data,
        "summary": {
            "total_files_parsed": total,
            "total_files_failed": failed,
        },
    }

def save_ast(workspace_dir, repo_name, ast_data):
    if ast_data is None:
        return None
    ast_dir = os.path.join(workspace_dir, repo_name, "ast")
    os.makedirs(ast_dir, exist_ok=True)

    manifest_path = os.path.join(ast_dir, "ast.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(ast_data, f, indent=2, ensure_ascii=False)

    return manifest_path

def show_parse_summary(repo_name, ast_data):
    if ast_data is None:
        print(f"  {DIM}[*]{RST} AST parsing skipped.")
        return
    summary = ast_data["summary"]
    total = summary["total_files_parsed"]
    failed = summary["total_files_failed"]
    print(f"  {GRN}[+]{RST} {WHT}{repo_name}{RST}: parsed {total} files"
          + (f" ({failed} failed)" if failed else ""))
