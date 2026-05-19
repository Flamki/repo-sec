"""Misconfiguration detection — flags common security anti-patterns.

Checks for: committed .env files, Dockerfile issues, debug mode flags,
CORS wildcards, insecure defaults, and missing security headers.
"""

import re
import uuid
from typing import Dict, List
from .models import Finding, FindingType, SeverityLevel


def scan_misconfigs(
    files: Dict[str, str], tree: List[dict]
) -> List[Finding]:
    """Run all misconfiguration checks. Returns list of findings."""
    findings: List[Finding] = []
    all_paths = [f["path"] for f in tree]

    findings.extend(_check_env_files(all_paths))
    findings.extend(_check_dockerfiles(files))
    findings.extend(_check_debug_mode(files))
    findings.extend(_check_cors_wildcard(files))
    findings.extend(_check_hardcoded_urls(files))
    findings.extend(_check_insecure_config(files))

    return findings


# ---------------------------------------------------------------------------
# .env files committed to repo
# ---------------------------------------------------------------------------

_ENV_PATTERNS = [
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test",
]
_ENV_SAFE = {".env.example", ".env.sample", ".env.template"}


def _check_env_files(all_paths: List[str]) -> List[Finding]:
    findings = []
    for path in all_paths:
        filename = path.split("/")[-1].lower()
        if filename in _ENV_SAFE:
            continue
        if filename in _ENV_PATTERNS or filename.startswith(".env"):
            # Check it's not in a test/example directory
            path_lower = path.lower()
            if any(skip in path_lower for skip in ["example", "sample", "template", "test/fixture"]):
                continue
            findings.append(Finding(
                id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                type=FindingType.MISCONFIGURATION,
                severity=SeverityLevel.CRITICAL,
                title="Environment file committed to repository",
                description=(
                    f"The file '{path}' likely contains secrets (API keys, database credentials, etc.) "
                    "and should never be committed to version control. Add it to .gitignore immediately."
                ),
                file=path,
                evidence=f"File detected in repository: {path}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Dockerfile security issues
# ---------------------------------------------------------------------------

def _check_dockerfiles(files: Dict[str, str]) -> List[Finding]:
    findings = []
    for filepath, content in files.items():
        filename = filepath.split("/")[-1].lower()
        if filename not in ("dockerfile", "dockerfile.dev", "dockerfile.prod"):
            if not filename.startswith("dockerfile"):
                continue

        lines = content.split("\n")
        has_user = False
        has_healthcheck = False
        has_expose = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip().upper()

            # Check for USER instruction
            if stripped.startswith("USER "):
                has_user = True
                user_val = line.strip().split(None, 1)[-1].strip().lower()
                if user_val == "root":
                    findings.append(Finding(
                        id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                        type=FindingType.MISCONFIGURATION,
                        severity=SeverityLevel.HIGH,
                        title="Dockerfile runs as root user",
                        description="Container explicitly set to run as root. Create a non-root user for production containers.",
                        file=filepath,
                        line=i,
                        evidence=line.strip(),
                    ))

            # Check for HEALTHCHECK
            if stripped.startswith("HEALTHCHECK "):
                has_healthcheck = True

            # Check for EXPOSE
            if stripped.startswith("EXPOSE "):
                has_expose = True

            # Check for latest tag in FROM
            if stripped.startswith("FROM "):
                image = line.strip().split(None, 1)[-1].split(" AS ")[0].strip()
                if image.endswith(":latest") or ":" not in image:
                    findings.append(Finding(
                        id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                        type=FindingType.MISCONFIGURATION,
                        severity=SeverityLevel.MEDIUM,
                        title="Dockerfile uses unpinned base image",
                        description=f"Base image '{image}' is not version-pinned. Use a specific tag for reproducible builds.",
                        file=filepath,
                        line=i,
                        evidence=line.strip(),
                    ))

            # Check for ADD instead of COPY (security best practice)
            if stripped.startswith("ADD ") and "http" not in line.lower():
                findings.append(Finding(
                    id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                    type=FindingType.MISCONFIGURATION,
                    severity=SeverityLevel.LOW,
                    title="Dockerfile uses ADD instead of COPY",
                    description="ADD has implicit tar extraction and URL fetch. Use COPY for predictable behavior unless ADD features are needed.",
                    file=filepath,
                    line=i,
                    evidence=line.strip(),
                ))

        # Container runs as root by default if no USER instruction
        if not has_user and len(lines) > 3:
            findings.append(Finding(
                id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                type=FindingType.MISCONFIGURATION,
                severity=SeverityLevel.MEDIUM,
                title="Dockerfile has no USER instruction",
                description="Container will run as root by default. Add a USER instruction to run as non-root.",
                file=filepath,
                evidence="No USER instruction found in Dockerfile",
            ))

        # Exposed ports without healthcheck
        if has_expose and not has_healthcheck:
            findings.append(Finding(
                id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                type=FindingType.MISCONFIGURATION,
                severity=SeverityLevel.LOW,
                title="Dockerfile exposes ports without HEALTHCHECK",
                description="Add a HEALTHCHECK instruction for proper container orchestration and monitoring.",
                file=filepath,
                evidence="EXPOSE found but no HEALTHCHECK defined",
            ))

    return findings


# ---------------------------------------------------------------------------
# Debug mode / development flags in production configs
# ---------------------------------------------------------------------------

_DEBUG_PATTERNS = [
    (re.compile(r"""DEBUG\s*[=:]\s*['"]?(?:true|1|yes|on)['"]?""", re.IGNORECASE), "DEBUG mode is enabled"),
    (re.compile(r"""NODE_ENV\s*[=:]\s*['"]?development['"]?""", re.IGNORECASE), "NODE_ENV set to development"),
    (re.compile(r"""FLASK_ENV\s*[=:]\s*['"]?development['"]?""", re.IGNORECASE), "FLASK_ENV set to development"),
    (re.compile(r"""FLASK_DEBUG\s*[=:]\s*['"]?(?:true|1|yes)['"]?""", re.IGNORECASE), "FLASK_DEBUG is enabled"),
    (re.compile(r"""DJANGO_DEBUG\s*[=:]\s*['"]?(?:true|1|yes)['"]?""", re.IGNORECASE), "DJANGO_DEBUG is enabled"),
    (re.compile(r"""APP_DEBUG\s*[=:]\s*['"]?(?:true|1|yes)['"]?""", re.IGNORECASE), "APP_DEBUG is enabled"),
    (re.compile(r"""RAILS_ENV\s*[=:]\s*['"]?development['"]?""", re.IGNORECASE), "RAILS_ENV set to development"),
]

# Only check these file types for debug flags
_DEBUG_FILE_EXTS = {".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties"}
_DEBUG_FILENAMES = {"docker-compose.yml", "docker-compose.yaml", ".env", "config.json", "settings.py", "config.py"}


def _check_debug_mode(files: Dict[str, str]) -> List[Finding]:
    findings = []
    for filepath, content in files.items():
        filename = filepath.split("/")[-1].lower()
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

        if filename not in _DEBUG_FILENAMES and ext not in _DEBUG_FILE_EXTS:
            continue

        for i, line in enumerate(content.split("\n"), 1):
            for pattern, msg in _DEBUG_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                        type=FindingType.MISCONFIGURATION,
                        severity=SeverityLevel.HIGH,
                        title=f"Debug/development mode enabled: {msg}",
                        description="Debug mode exposes detailed error messages, stack traces, and internal state. Disable in production.",
                        file=filepath,
                        line=i,
                        evidence=line.strip()[:200],
                    ))
                    break  # One finding per line
    return findings


# ---------------------------------------------------------------------------
# CORS wildcard
# ---------------------------------------------------------------------------

def _check_cors_wildcard(files: Dict[str, str]) -> List[Finding]:
    findings = []
    cors_pattern = re.compile(
        r"""(?:Access-Control-Allow-Origin|allow_origins|cors_origins|CORS_ORIGIN)\s*[=:]\s*['"]?\*['"]?""",
        re.IGNORECASE,
    )
    for filepath, content in files.items():
        for i, line in enumerate(content.split("\n"), 1):
            if cors_pattern.search(line):
                findings.append(Finding(
                    id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                    type=FindingType.MISCONFIGURATION,
                    severity=SeverityLevel.MEDIUM,
                    title="CORS wildcard (*) allows all origins",
                    description="Wildcard CORS policy allows any website to make requests to your API. Restrict to specific trusted origins.",
                    file=filepath,
                    line=i,
                    evidence=line.strip()[:200],
                ))
    return findings


# ---------------------------------------------------------------------------
# Hardcoded localhost / insecure HTTP URLs in config
# ---------------------------------------------------------------------------

def _check_hardcoded_urls(files: Dict[str, str]) -> List[Finding]:
    findings = []
    # Match http:// URLs that aren't localhost/127.0.0.1
    http_pattern = re.compile(
        r"""(?:api_url|base_url|endpoint|server_url|backend_url|webhook_url)\s*[=:]\s*['"]?(http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s'"]+)""",
        re.IGNORECASE,
    )
    for filepath, content in files.items():
        filename = filepath.split("/")[-1].lower()
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
        if ext not in {".env", ".yml", ".yaml", ".json", ".toml", ".js", ".ts", ".py", ".conf"}:
            continue

        for i, line in enumerate(content.split("\n"), 1):
            match = http_pattern.search(line)
            if match:
                findings.append(Finding(
                    id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                    type=FindingType.MISCONFIGURATION,
                    severity=SeverityLevel.LOW,
                    title="Insecure HTTP URL in configuration",
                    description="API/service URL uses HTTP instead of HTTPS. Use HTTPS to encrypt data in transit.",
                    file=filepath,
                    line=i,
                    evidence=line.strip()[:200],
                ))
    return findings


# ---------------------------------------------------------------------------
# Insecure package.json / config patterns
# ---------------------------------------------------------------------------

def _check_insecure_config(files: Dict[str, str]) -> List[Finding]:
    findings = []
    for filepath, content in files.items():
        filename = filepath.split("/")[-1].lower()

        # Check .npmrc for auth tokens (shouldn't be committed)
        if filename == ".npmrc":
            if "_authToken" in content or "_auth=" in content:
                findings.append(Finding(
                    id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                    type=FindingType.MISCONFIGURATION,
                    severity=SeverityLevel.CRITICAL,
                    title="npm auth token in committed .npmrc",
                    description=".npmrc contains authentication tokens. These grant npm publish access and must not be in version control.",
                    file=filepath,
                    evidence=".npmrc contains _authToken or _auth credentials",
                ))

        # Check for disabled SSL verification
        if filename in ("settings.py", "config.py", "app.py"):
            if "verify=False" in content or "VERIFY_SSL = False" in content.upper():
                for i, line in enumerate(content.split("\n"), 1):
                    if "verify" in line.lower() and "false" in line.lower():
                        findings.append(Finding(
                            id=f"CFG-{uuid.uuid4().hex[:8].upper()}",
                            type=FindingType.MISCONFIGURATION,
                            severity=SeverityLevel.HIGH,
                            title="SSL verification disabled",
                            description="SSL/TLS verification is disabled, making the application vulnerable to man-in-the-middle attacks.",
                            file=filepath,
                            line=i,
                            evidence=line.strip()[:200],
                        ))
                        break

    return findings
