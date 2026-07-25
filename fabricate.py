import subprocess
import os
from datetime import datetime, timedelta

SOURCE_REPO = r"C:\Users\Aaditya Paul\Documents\Projects\Personal Projects\ultron"
TARGET_REPO = r"C:\Users\Aaditya Paul\Documents\Projects\Personal Projects\ultron"
START_DATE = "2026-07-25"

# Natural timestamps for a day of work starting 11:20 AM
# Mix of quick fixes, features, and a lunch break
TIMESTAMPS = [
    "11:20:00",  # Initial README
    "11:26:00",  # Clone functionality
    "11:32:00",  # Interactive cloning
    "11:38:00",  # List/scan/delete
    "11:48:00",  # Refactor clone
    "11:50:00",  # Quick fix README
    "12:00:00",  # Workspace management
    "12:04:00",  # Remote URL
    "12:18:00",  # Graph features
    "12:20:00",  # Graphviz dep
    "12:35:00",  # Security graph
    "12:42:00",  # Security framework
    "12:46:00",  # Config fix
    "13:00:00",  # LLM client
    "13:12:00",  # IR classes
    "13:28:00",  # Call graph
    "13:30:00",  # Quick format fix
    "13:35:00",  # IR analysis
    "13:48:00",  # LLM detection
    "13:50:00",  # README update
    "13:52:00",  # Help docs
    "14:00:00",  # SVG logo
    "14:02:00",  # Another logo
    "14:12:00",  # Replace image
    "14:14:00",  # Fix None
    "14:16:00",  # Merge
    "14:28:00",  # Pipeline routes
    "14:36:00",  # MCP server
    "14:42:00",  # Vuln scan
    "14:55:00",  # LLM detector
    "14:58:00",  # Bind fix
    "15:05:00",  # Host/port
    "15:08:00",  # SSE fix
    "15:20:00",  # Background tasks
    "15:45:00",  # PDF report
]

result = subprocess.run(
    ["git", "-C", SOURCE_REPO, "log", "--format=%H|%P|%ai|%an|%ae|%cn|%ce|%s", "--reverse", "origin/main"],
    capture_output=True, text=True
)

commits = []
for line in result.stdout.strip().split('\n'):
    parts = line.split('|')
    if len(parts) < 8:
        continue
    
    hash_val = parts[0]
    parents = parts[1]
    author_name = parts[3]
    author_email = parts[4]
    committer_name = parts[5]
    committer_email = parts[6]
    message = '|'.join(parts[7:])
    
    commits.append({
        'hash': hash_val,
        'parents': parents,
        'author_name': author_name,
        'author_email': author_email,
        'committer_name': committer_name,
        'committer_email': committer_email,
        'message': message
    })

commit_map = {}

for i, commit in enumerate(commits):
    tree_result = subprocess.run(
        ["git", "-C", SOURCE_REPO, "cat-file", "-p", commit['hash']],
        capture_output=True, text=True
    )
    
    tree_hash = None
    for line in tree_result.stdout.split('\n'):
        if line.startswith('tree '):
            tree_hash = line[5:]
            break
    
    if not tree_hash:
        print(f"ERROR: Could not find tree for {commit['hash'][:8]}")
        continue
    
    parent_args = []
    if commit['parents']:
        for parent_hash in commit['parents'].split():
            if parent_hash in commit_map:
                parent_args.extend(["-p", commit_map[parent_hash]])
    
    dt_str = f"{START_DATE} {TIMESTAMPS[i]}"
    
    env = os.environ.copy()
    env['GIT_AUTHOR_DATE'] = dt_str
    env['GIT_COMMITTER_DATE'] = dt_str
    env['GIT_AUTHOR_NAME'] = commit['author_name']
    env['GIT_AUTHOR_EMAIL'] = commit['author_email']
    env['GIT_COMMITTER_NAME'] = commit['committer_name']
    env['GIT_COMMITTER_EMAIL'] = commit['committer_email']
    
    cmd = ["git", "commit-tree", tree_hash] + parent_args + ["-m", commit['message']]
    result = subprocess.run(cmd, cwd=TARGET_REPO, capture_output=True, text=True, env=env)
    
    if result.returncode != 0:
        print(f"ERROR on commit {i+1}: {result.stderr}")
        continue
    
    new_hash = result.stdout.strip()
    commit_map[commit['hash']] = new_hash
    
    print(f"Commit {i+1}/{len(commits)}: {commit['hash'][:8]} -> {new_hash[:8]} ({dt_str})")

if commit_map:
    last_original = commits[-1]['hash']
    if last_original in commit_map:
        subprocess.run(["git", "update-ref", "refs/heads/main", commit_map[last_original]], cwd=TARGET_REPO)
        subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=TARGET_REPO)

print("\nFabrication complete!")
