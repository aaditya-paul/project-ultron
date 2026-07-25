import os
import json
from datetime import datetime

from colors import GRN, CYAN, BOLD, DIM, WHT, RST, YLW

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
    ".jsx":   "JavaScript",
    ".ts":    "TypeScript",
    ".tsx":   "TypeScript",
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
}

NON_LANG_EXTENSIONS = {".json", ".yml", ".yaml", ".md", ".txt", ".cfg", ".ini", ".conf", ".toml", ".lock"}

FRAMEWORK_CHECKS = [
    ("Django",  lambda r: _has_file(r, "manage.py") or _has_dep(r, "django")),
    ("Flask",   lambda r: _has_dep(r, "flask")),
    ("FastAPI", lambda r: _has_dep(r, "fastapi")),
    ("Pyramid", lambda r: _has_dep(r, "pyramid")),
    ("React",   lambda r: _has_dep(r, "react") or _has_glob(r, "*.jsx") or _has_glob(r, "*.tsx")),
    ("Vue.js",  lambda r: _has_dep(r, "vue") or _has_glob(r, "*.vue")),
    ("Angular", lambda r: _has_file(r, "angular.json") or _has_dep(r, "@angular/core")),
    ("Next.js", lambda r: _has_dep(r, "next")),
    ("Nuxt.js", lambda r: _has_dep(r, "nuxt")),
    ("Express", lambda r: _has_dep(r, "express")),
    ("NestJS",  lambda r: _has_dep(r, "@nestjs/core")),
    ("Electron", lambda r: _has_dep(r, "electron")),
    ("Spring Boot", lambda r: _has_dep(r, "spring-boot-starter") or _has_file(r, "spring-boot-starter")),
    ("Laravel", lambda r: _has_file(r, "artisan") or _has_dep(r, "laravel/framework")),
    ("Symfony", lambda r: _has_dep(r, "symfony/symfony") or _has_dep(r, "symfony/framework-bundle")),
    ("Rails",   lambda r: _has_dep(r, "rails") or _has_file(r, "config/routes.rb")),
    ("Gin",     lambda r: _has_dep(r, "gin-gonic/gin")),
    ("Echo",    lambda r: _has_dep(r, "labstack/echo")),
    ("Fiber",   lambda r: _has_dep(r, "gofiber/fiber")),
    ("Actix Web",  lambda r: _has_dep(r, "actix-web")),
    ("Rocket",     lambda r: _has_dep(r, "rocket")),
    ("Axum",       lambda r: _has_dep(r, "axum")),
    ("Tokio",      lambda r: _has_dep(r, "tokio")),
]

WORKSPACE_DIR = os.path.join(os.getcwd(), "workspace")

def _root_files(repo_path):
    try:
        return set(os.listdir(repo_path))
    except PermissionError:
        return set()

def _has_file(repo_path, name):
    return os.path.isfile(os.path.join(repo_path, name))

def _has_glob(repo_path, pattern):
    ext = pattern.lstrip("*.")
    for dirpath, _, filenames in os.walk(repo_path):
        if dirpath.replace(repo_path, "").count(os.sep) > 3:
            continue
        for f in filenames:
            if f.endswith(ext):
                return True
    return False

def _has_dep(repo_path, dep_name):
    dep_name = dep_name.lower()

    pkg_json = os.path.join(repo_path, "package.json")
    if os.path.isfile(pkg_json):
        try:
            with open(pkg_json, encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for key in data.get(section, {}):
                    if dep_name in key.lower():
                        return True
        except Exception:
            pass

    req_txt = os.path.join(repo_path, "requirements.txt")
    if os.path.isfile(req_txt):
        try:
            with open(req_txt, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        pkg = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
                        if dep_name in pkg:
                            return True
        except Exception:
            pass

    pyproject = os.path.join(repo_path, "pyproject.toml")
    if os.path.isfile(pyproject):
        try:
            with open(pyproject, encoding="utf-8", errors="ignore") as f:
                if dep_name in f.read().lower():
                    return True
        except Exception:
            pass

    setup_py = os.path.join(repo_path, "setup.py")
    if os.path.isfile(setup_py):
        try:
            with open(setup_py, encoding="utf-8", errors="ignore") as f:
                if dep_name in f.read().lower():
                    return True
        except Exception:
            pass

    cargo = os.path.join(repo_path, "Cargo.toml")
    if os.path.isfile(cargo):
        try:
            with open(cargo, encoding="utf-8", errors="ignore") as f:
                if dep_name in f.read().lower():
                    return True
        except Exception:
            pass

    go_mod = os.path.join(repo_path, "go.mod")
    if os.path.isfile(go_mod):
        try:
            with open(go_mod, encoding="utf-8", errors="ignore") as f:
                if dep_name in f.read().lower():
                    return True
        except Exception:
            pass

    composer = os.path.join(repo_path, "composer.json")
    if os.path.isfile(composer):
        try:
            with open(composer, encoding="utf-8", errors="ignore") as f:
                if dep_name in f.read().lower():
                    return True
        except Exception:
            pass

    gemfile = os.path.join(repo_path, "Gemfile")
    if os.path.isfile(gemfile):
        try:
            with open(gemfile, encoding="utf-8", errors="ignore") as f:
                if dep_name in f.read().lower():
                    return True
        except Exception:
            pass

    build_gradle = os.path.join(repo_path, "build.gradle")
    if os.path.isfile(build_gradle):
        try:
            with open(build_gradle, encoding="utf-8", errors="ignore") as f:
                if dep_name in f.read().lower():
                    return True
        except Exception:
            pass

    return False

def _detect_languages(repo_path):
    detected = set()
    root = _root_files(repo_path)

    for lang, markers in LANGUAGE_SIGNATURES:
        for marker in markers:
            if marker.startswith("*."):
                ext = marker[1:]
                if any(f.endswith(ext) for f in root):
                    detected.add(lang)
                    break
            elif marker in root:
                detected.add(lang)
                break

    ext_counts = {}
    for dirpath, _, filenames in os.walk(repo_path):
        depth = dirpath.replace(repo_path, "").count(os.sep)
        if depth > 4:
            continue
        for f in filenames:
            ext = os.path.splitext(f)[1].lower()
            if ext in NON_LANG_EXTENSIONS:
                continue
            lang = EXTENSION_MAP.get(ext)
            if lang:
                ext_counts[lang] = ext_counts.get(lang, 0) + 1

    for lang, count in ext_counts.items():
        if count >= 3:
            detected.add(lang)

    priority = ["Node.js", "Python", "Java", "Go", "Rust", "PHP", "Ruby", ".NET (C#)", "C / C++"]
    def _key(l):
        try:
            return (0, priority.index(l))
        except ValueError:
            return (1, l)

    return sorted(detected, key=_key)

def _detect_frameworks(repo_path):
    detected = []
    for name, check in FRAMEWORK_CHECKS:
        try:
            if check(repo_path):
                detected.append(name)
        except Exception:
            pass
    return detected

def analyze_project(repo_path):
    languages = _detect_languages(repo_path)
    frameworks = _detect_frameworks(repo_path)
    return {"languages": languages, "frameworks": frameworks}

def save_workspace_manifest(repo_name, repo_url, analysis):
    ws_dir = os.path.join(WORKSPACE_DIR, repo_name)
    os.makedirs(ws_dir, exist_ok=True)

    manifest_path = os.path.join(ws_dir, "manifest.json")
    manifest = {
        "name": repo_name,
        "source_url": repo_url,
        "clone_path": os.path.join(os.getcwd(), "clones", repo_name),
        "languages": analysis["languages"],
        "frameworks": analysis["frameworks"],
        "detected_at": datetime.now().isoformat(),
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest_path

def show_detected_types(repo_name, analysis):
    langs = analysis["languages"]
    frameworks = analysis["frameworks"]

    if not langs:
        print(f"  {DIM}[*]{RST} {WHT}{repo_name}{RST}: no project types detected.")
        return

    print(f"  {DIM}[*]{RST} {WHT}{repo_name}{RST} project types:")
    for l in langs:
        print(f"    {GRN}•{RST} {CYAN}{l}{RST}")
    if frameworks:
        print(f"  {DIM}[*]{RST} detected frameworks:")
        for fw in frameworks:
            print(f"    {GRN}•{RST} {YLW}{fw}{RST}")
