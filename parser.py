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
    },
    "JavaScript": {
        "function":   ("function_declaration", "arrow_function", "method_definition"),
        "class":      "class_declaration",
        "import":     ("import_statement", "import_expression"),
        "call":       "call_expression",
    },
    "TypeScript": {
        "function":   ("function_declaration", "arrow_function", "method_definition"),
        "class":      "class_declaration",
        "import":     ("import_statement", "import_expression"),
        "call":       "call_expression",
    },
    "TSX": {
        "function":   ("function_declaration", "arrow_function", "method_definition"),
        "class":      "class_declaration",
        "import":     ("import_statement", "import_expression"),
        "call":       "call_expression",
    },
    "Go": {
        "function":   "function_declaration",
        "class":      "type_declaration",
        "import":     "import_declaration",
        "call":       "call_expression",
    },
    "Rust": {
        "function":   "function_item",
        "class":      "struct_item",
        "import":     "use_declaration",
        "call":       "call_expression",
    },
    "Java": {
        "function":   "method_declaration",
        "class":      "class_declaration",
        "import":     "import_declaration",
        "call":       "method_invocation",
    },
    "C#": {
        "function":   ("method_declaration", "local_function_statement"),
        "class":      "class_declaration",
        "import":     "using_directive",
        "call":       "invocation_expression",
    },
    "C": {
        "function":   ("function_definition", "declaration"),
        "class":      "struct_specifier",
        "import":     ("preproc_include", "include_next"),
        "call":       "call_expression",
    },
    "C++": {
        "function":   ("function_definition", "declaration"),
        "class":      ("class_specifier", "struct_specifier"),
        "import":     ("preproc_include", "include_next"),
        "call":       "call_expression",
    },
    "PHP": {
        "function":   "function_definition",
        "class":      "class_declaration",
        "import":     ("include_expression", "require_expression"),
        "call":       "function_call_expression",
    },
    "Ruby": {
        "function":   ("method", "singleton_method"),
        "class":      "class",
        "import":     "require",
        "call":       "call",
    },
    "Kotlin": {
        "function":   ("function_declaration", "named_function"),
        "class":      "class_declaration",
        "import":     "import_header",
        "call":       "call_expression",
    },
    "Swift": {
        "function":   "function_declaration",
        "class":      "class_declaration",
        "import":     "import_declaration",
        "call":       "call_expression",
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

    if isinstance(func_types, str):
        func_types = (func_types,)
    if isinstance(class_types, str):
        class_types = (class_types,)
    if isinstance(import_types, str):
        import_types = (import_types,)
    if isinstance(call_types, str):
        call_types = (call_types,)

    func_set = set(func_types)
    class_set = set(class_types)
    import_set = set(import_types)
    call_set = set(call_types)

    result = {
        "language": lang_name,
        "functions": [],
        "classes": [],
        "imports": [],
        "calls": [],
    }

    for node in _find_children(root, func_set):
        name, is_anon = _extract_name(node, source)
        params = _extract_params(node, source)
        result["functions"].append({
            "name": name or "",
            "params": params,
            "line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "anonymous": is_anon,
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
            result["calls"].append(text)

    return result

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
