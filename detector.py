import os

from colors import GRN, CYAN, BOLD, DIM, WHT, RST

LANGUAGE_SIGNATURES = [
    ("Node.js",        ["package.json", "yarn.lock", "pnpm-lock.yaml"]),
    ("Python",         ["requirements.txt", "setup.py", "pyproject.toml", "setup.cfg", "Pipfile", "Pipfile.lock"]),
    ("Java",           ["pom.xml", "build.gradle", "settings.gradle", "gradlew"]),
    ("Go",             ["go.mod", "go.sum"]),
    ("Rust",           ["Cargo.toml", "Cargo.lock"]),
    ("PHP",            ["composer.json", "composer.lock"]),
    ("Ruby",           ["Gemfile", "Gemfile.lock"]),
    (".NET (C#)",      ["*.sln", "*.csproj"]),
    ("C / C++",        ["CMakeLists.txt", "Makefile", "configure.ac"]),
    ("Kotlin",         ["build.gradle.kts"]),
    ("Swift",          ["Package.swift"]),
    ("Terraform",      ["*.tf"]),
    ("Docker",         ["Dockerfile", "docker-compose.yml"]),
]

EXTENSION_MAP = {
    ".py":    "Python",
    ".js":    "JavaScript",
    ".jsx":   "JavaScript (React)",
    ".ts":    "TypeScript",
    ".tsx":   "TypeScript (React)",
    ".vue":   "Vue.js",
    ".java":  "Java",
    ".go":    "Go",
    ".rs":    "Rust",
    ".php":   "PHP",
    ".rb":    "Ruby",
    ".cs":    "C#",
    ".c":     "C",
    ".h":     "C / C++",
    ".cpp":   "C++",
    ".cc":    "C++",
    ".cxx":   "C++",
    ".kt":    "Kotlin",
    ".swift": "Swift",
    ".tf":    "Terraform",
    ".sh":    "Shell",
    ".yml":   "YAML",
    ".yaml":  "YAML",
    ".json":  "JSON",
    ".md":    "Markdown",
}

def detect_project_types(repo_path):
    detected = set()

    if not os.path.isdir(repo_path):
        return []

    root_files = set()
    try:
        root_files = set(os.listdir(repo_path))
    except PermissionError:
        pass

    for lang, markers in LANGUAGE_SIGNATURES:
        for marker in markers:
            if marker.startswith("*."):
                ext = marker[1:]
                for f in root_files:
                    if f.endswith(ext):
                        detected.add(lang)
                        break
                if lang in detected:
                    break
            elif marker in root_files:
                detected.add(lang)
                break

    ext_counts = {}
    for dirpath, _, filenames in os.walk(repo_path):
        depth = dirpath.replace(repo_path, "").count(os.sep)
        if depth > 4:
            continue
        for f in filenames:
            ext = os.path.splitext(f)[1].lower()
            if ext in EXTENSION_MAP:
                lang = EXTENSION_MAP[ext]
                ext_counts[lang] = ext_counts.get(lang, 0) + 1

    for lang, count in ext_counts.items():
        if count >= 3:
            detected.add(lang)

    return sorted(detected, key=_sort_key)

def _sort_key(lang):
    priority = ["Node.js", "Python", "Java", "Go", "Rust", "PHP", "Ruby", ".NET (C#)", "C / C++"]
    try:
        return (0, priority.index(lang))
    except ValueError:
        return (1, lang)

def show_detected_types(repo_name, types):
    if not types:
        print(f"  {DIM}[*]{RST} {WHT}{repo_name}{RST}: no project types detected.")
        return

    print(f"  {DIM}[*]{RST} {WHT}{repo_name}{RST} project types:")
    for t in types:
        print(f"    {GRN}•{RST} {CYAN}{t}{RST}")
