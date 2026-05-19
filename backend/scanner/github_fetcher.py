"""GitHub API client — fetches repo file trees and content."""

import httpx
import base64
import re
from typing import Dict, List, Tuple, Optional

# Extensions worth scanning (skip binaries, images, fonts, etc.)
SCANNABLE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".go", ".java", ".rs",
    ".php", ".cs", ".c", ".cpp", ".h", ".swift", ".kt", ".scala",
    ".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg", ".conf",
    ".env", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".sql", ".graphql", ".prisma", ".proto",
    ".md", ".txt", ".rst", ".csv",
    ".html", ".css", ".scss", ".less",
    ".tf", ".hcl", ".dockerfile",
    ".gradle", ".properties", ".pom",
    ".gemfile", ".gemspec", ".lock",
    ".pip", ".pipfile", ".cfg",
}

# Filenames always worth scanning (no extension check needed)
SCANNABLE_FILENAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.example", ".env.test",
    "makefile", "procfile", "vagrantfile",
    "package.json", "package-lock.json",
    "requirements.txt", "pipfile", "pipfile.lock", "setup.py", "setup.cfg",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "gemfile", "gemfile.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    ".gitignore", ".dockerignore", ".npmrc", ".yarnrc",
    "nginx.conf", "httpd.conf", "apache2.conf",
}

# Directories to skip entirely
SKIP_DIRS = {
    "node_modules", "vendor", ".git", "__pycache__", ".next",
    "dist", "build", ".cache", "coverage", ".tox", ".mypy_cache",
    "venv", ".venv", "env", ".env_dir", "bower_components",
    ".terraform", ".gradle", "target",
}

MAX_FILES = 150
MAX_FILE_SIZE = 500_000  # 500KB


def parse_repo_url(url: str) -> Tuple[str, str]:
    """Extract owner/repo from a GitHub URL."""
    url = url.strip().rstrip("/")
    # Remove .git suffix
    if url.endswith(".git"):
        url = url[:-4]
    # Handle various URL formats
    patterns = [
        r"github\.com/([^/]+)/([^/]+)",
        r"^([^/]+)/([^/]+)$",
    ]
    for pat in patterns:
        m = re.search(pat, url)
        if m:
            return m.group(1), m.group(2)
    raise ValueError(f"Cannot parse GitHub repo URL: {url}")


def _should_scan_file(path: str) -> bool:
    """Check if a file path is worth scanning."""
    parts = path.lower().split("/")
    # Skip files inside excluded directories
    for part in parts[:-1]:
        if part in SKIP_DIRS:
            return False
    filename = parts[-1].lower()
    # Always scan known filenames
    if filename in SCANNABLE_FILENAMES:
        return True
    # Check extension
    for ext in SCANNABLE_EXTENSIONS:
        if filename.endswith(ext):
            return True
    # Files with no extension might be configs
    if "." not in filename and filename not in {"license", "readme", "changelog"}:
        return True
    return False


async def fetch_file_tree(owner: str, repo: str) -> List[dict]:
    """Fetch the full recursive file tree from GitHub API.

    Returns list of dicts with keys: path, size, type, sha
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "repo-sec-scanner/1.0",
        })
        if resp.status_code == 404:
            raise ValueError(f"Repository {owner}/{repo} not found or is private")
        if resp.status_code == 403:
            raise ValueError("GitHub API rate limit exceeded. Try again later.")
        resp.raise_for_status()

    data = resp.json()
    tree = data.get("tree", [])
    # Filter to blobs (files) only
    return [
        {"path": item["path"], "size": item.get("size", 0),
         "type": item["type"], "sha": item.get("sha", "")}
        for item in tree
        if item["type"] == "blob"
    ]


async def download_files(
    owner: str, repo: str, tree: List[dict]
) -> Dict[str, str]:
    """Download file contents for scannable files.

    Uses raw.githubusercontent.com (no rate limit).
    Returns dict of {filepath: content_string}.
    """
    # Filter and prioritize files
    candidates = [
        f for f in tree
        if _should_scan_file(f["path"]) and f["size"] <= MAX_FILE_SIZE
    ]
    # Sort by relevance: config/manifest files first, then by size (small first)
    def priority(f):
        name = f["path"].split("/")[-1].lower()
        if name in SCANNABLE_FILENAMES:
            return (0, f["size"])
        return (1, f["size"])

    candidates.sort(key=priority)
    candidates = candidates[:MAX_FILES]

    files: Dict[str, str] = {}
    base_url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD"

    import asyncio

    async def _fetch_one(client: httpx.AsyncClient, item: dict) -> Optional[tuple]:
        try:
            resp = await client.get(
                f"{base_url}/{item['path']}",
                headers={"User-Agent": "repo-sec-scanner/1.0"},
            )
            if resp.status_code != 200:
                return None
            content_type = resp.headers.get("content-type", "")
            if "image" in content_type or "octet-stream" in content_type:
                return None
            text = resp.text
            if "\x00" in text[:1000]:
                return None
            return (item["path"], text)
        except (httpx.TimeoutException, httpx.HTTPError):
            return None

    # Download concurrently in batches of 20
    CONCURRENCY = 20
    async with httpx.AsyncClient(timeout=15.0, limits=httpx.Limits(max_connections=CONCURRENCY)) as client:
        for batch_start in range(0, len(candidates), CONCURRENCY):
            batch = candidates[batch_start:batch_start + CONCURRENCY]
            results = await asyncio.gather(
                *[_fetch_one(client, item) for item in batch],
                return_exceptions=True,
            )
            for result in results:
                if isinstance(result, tuple) and result is not None:
                    files[result[0]] = result[1]

    return files
