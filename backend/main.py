"""repo-sec — AI-Powered GitHub Repository Security Scanner.

FastAPI backend that orchestrates the scan pipeline:
1. Fetch repo file tree via GitHub API
2. Download scannable files via raw.githubusercontent.com
3. Run three parallel scan stages (secrets, deps, misconfigs)
4. Aggregate findings, calculate severity, generate fix suggestions
5. Return structured JSON matching the frontend schema
"""

import uuid
import time
import json
import os
from datetime import datetime, timezone
from typing import List, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from scanner.models import (
    Finding, FixSuggestion, ScanResult, ScanRequest,
    SeverityLevel, FindingType,
)
from scanner.github_fetcher import parse_repo_url, fetch_file_tree, download_files
from scanner.secrets_scanner import scan_secrets
from scanner.dependency_scanner import scan_dependencies
from scanner.misconfig_scanner import scan_misconfigs
from scanner.sast_scanner import scan_sast
from scanner.iac_scanner import scan_iac
from scanner.scorecard import compute_scorecard


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="repo-sec",
    description=(
        "AI-powered GitHub repository security scanner. "
        "Detects hardcoded secrets, vulnerable dependencies, and misconfigurations."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory scan store (most recent 50)
# ---------------------------------------------------------------------------

MAX_STORED_SCANS = 50
_scans: List[dict] = []


def _store_scan(result: dict):
    """Store a scan result, keeping only the most recent N."""
    _scans.insert(0, result)
    while len(_scans) > MAX_STORED_SCANS:
        _scans.pop()


# ---------------------------------------------------------------------------
# Severity calculator
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 4,
    SeverityLevel.HIGH: 3,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 1,
    SeverityLevel.CLEAN: 0,
}


def _calculate_overall_severity(findings: List[Finding]) -> SeverityLevel:
    """Overall severity = highest severity among all findings."""
    if not findings:
        return SeverityLevel.CLEAN
    max_sev = SeverityLevel.CLEAN
    for f in findings:
        if _SEVERITY_ORDER.get(f.severity, 0) > _SEVERITY_ORDER.get(max_sev, 0):
            max_sev = f.severity
    return max_sev


# ---------------------------------------------------------------------------
# Fix suggestion generator
# ---------------------------------------------------------------------------

_PRIORITY_MAP = {
    SeverityLevel.CRITICAL: "IMMEDIATE",
    SeverityLevel.HIGH: "HIGH",
    SeverityLevel.MEDIUM: "MEDIUM",
    SeverityLevel.LOW: "LOW",
}

_FIX_TEMPLATES = {
    FindingType.SECRET: {
        "action": "Rotate and revoke the exposed credential",
        "detail": (
            "1. Immediately revoke/rotate the exposed key in the provider's dashboard. "
            "2. Remove the secret from source code and Git history (use git-filter-repo or BFG). "
            "3. Store secrets in environment variables or a secrets manager (Vault, AWS Secrets Manager, etc.). "
            "4. Add a pre-commit hook (gitleaks/trufflehog) to prevent future leaks."
        ),
        "resources": [
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
            "https://github.com/gitleaks/gitleaks",
        ],
    },
    FindingType.VULNERABILITY: {
        "action": "Upgrade the vulnerable dependency",
        "detail": (
            "1. Check the CVE details for impact assessment. "
            "2. Update the dependency to the patched version specified in the advisory. "
            "3. Run your test suite to verify compatibility. "
            "4. Set up automated dependency scanning (Dependabot, Renovate) for ongoing protection."
        ),
        "resources": [
            "https://osv.dev/",
            "https://docs.github.com/en/code-security/dependabot",
        ],
    },
    FindingType.MISCONFIGURATION: {
        "action": "Fix the security misconfiguration",
        "detail": (
            "1. Review the flagged configuration against security best practices. "
            "2. Apply the recommended fix (see finding details). "
            "3. Ensure .env files are in .gitignore and never committed. "
            "4. Use CI/CD security gates to catch misconfigurations early."
        ),
        "resources": [
            "https://cheatsheetseries.owasp.org/",
            "https://docs.docker.com/develop/security-best-practices/",
        ],
    },
    FindingType.CODE_ISSUE: {
        "action": "Remediate the code security issue",
        "detail": (
            "1. Review the flagged code pattern and understand the vulnerability class (see CWE reference). "
            "2. Apply the secure coding alternative described in the finding. "
            "3. Use parameterized queries for SQL, safe APIs for OS commands, and input validation for user data. "
            "4. Add SAST tools (Semgrep, CodeQL) to your CI pipeline to catch these patterns automatically."
        ),
        "resources": [
            "https://cheatsheetseries.owasp.org/",
            "https://semgrep.dev/docs/",
            "https://cwe.mitre.org/",
        ],
    },
}


def _generate_fix_suggestions(findings: List[Finding]) -> List[FixSuggestion]:
    """Generate prioritized fix suggestions for each finding."""
    suggestions = []
    for finding in findings:
        template = _FIX_TEMPLATES.get(finding.type, _FIX_TEMPLATES[FindingType.MISCONFIGURATION])
        priority = _PRIORITY_MAP.get(finding.severity, "MEDIUM")

        # Customize action based on finding
        action = template["action"]
        detail = template["detail"]

        if finding.type == FindingType.VULNERABILITY and finding.cve:
            action = f"Upgrade {finding.title.replace('Vulnerable dependency: ', '')} — {finding.cve}"

        if finding.type == FindingType.SECRET:
            action = f"Revoke and rotate: {finding.title}"

        if finding.type == FindingType.MISCONFIGURATION:
            action = f"Fix: {finding.title}"

        suggestions.append(FixSuggestion(
            findingId=finding.id,
            priority=priority,
            action=action,
            detail=detail,
            resources=template["resources"],
        ))

    # Sort by priority (IMMEDIATE first)
    priority_order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    suggestions.sort(key=lambda s: priority_order.get(s.priority, 9))

    return suggestions


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "repo-sec", "version": "1.0.0"}


@app.get("/skill.json")
async def get_skill():
    """MCP discoverability manifest."""
    skill_path = Path(__file__).parent / "skill.json"
    if skill_path.exists():
        return FileResponse(str(skill_path), media_type="application/json")
    return JSONResponse(
        {"error": "skill.json not found"},
        status_code=404,
    )


@app.get("/scans")
async def list_scans():
    """List recent scan results."""
    return {"success": True, "data": _scans}


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get a specific scan result by ID."""
    for scan in _scans:
        if scan.get("scanId") == scan_id:
            return {"success": True, "data": scan}
    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")


@app.post("/scan")
async def run_scan(req: ScanRequest):
    """Execute a full security scan on a GitHub repository.

    Pipeline:
    1. Parse and validate the GitHub URL
    2. Fetch the repository file tree via GitHub API
    3. Download scannable file contents
    4. Run secrets detection (regex + entropy)
    5. Run dependency vulnerability scan (OSV.dev API)
    6. Run misconfiguration detection
    7. Aggregate findings and generate fix suggestions
    """
    start_time = time.time()

    # 1. Parse URL
    try:
        owner, repo = parse_repo_url(req.repo_url)
    except ValueError as e:
        return JSONResponse(
            {"success": False, "error": str(e)},
            status_code=400,
        )

    # 2. Fetch file tree
    try:
        tree = await fetch_file_tree(owner, repo)
    except ValueError as e:
        return JSONResponse(
            {"success": False, "error": str(e)},
            status_code=400,
        )
    except Exception as e:
        return JSONResponse(
            {"success": False, "error": f"Failed to fetch repository: {str(e)}"},
            status_code=502,
        )

    if not tree:
        return JSONResponse(
            {"success": False, "error": "Repository appears to be empty"},
            status_code=400,
        )

    # 3. Download files
    try:
        files = await download_files(owner, repo, tree)
    except Exception as e:
        return JSONResponse(
            {"success": False, "error": f"Failed to download files: {str(e)}"},
            status_code=502,
        )

    # 4-8. Run scan stages (5-stage pipeline)
    secret_findings = scan_secrets(files)

    try:
        dep_findings = await scan_dependencies(files)
    except Exception:
        dep_findings = []  # Don't fail entire scan if OSV.dev/EPSS is down

    misconfig_findings = scan_misconfigs(files, tree)
    sast_findings = scan_sast(files)
    iac_findings = scan_iac(files)

    # 9. Aggregate
    all_findings: List[Finding] = (
        secret_findings + dep_findings + misconfig_findings
        + sast_findings + iac_findings
    )
    overall_severity = _calculate_overall_severity(all_findings)
    fix_suggestions = _generate_fix_suggestions(all_findings)

    # 9. Compute Security Scorecard
    scorecard = compute_scorecard(files, tree, all_findings)

    duration_ms = int((time.time() - start_time) * 1000)

    result = ScanResult(
        scanId=str(uuid.uuid4()),
        repoUrl=req.repo_url.strip(),
        repoName=f"{owner}/{repo}",
        severity=overall_severity,
        findings=all_findings,
        fixSuggestions=fix_suggestions,
        filesScanned=len(files),
        findingsCount=len(all_findings),
        scannedAt=datetime.now(timezone.utc).isoformat(),
        durationMs=duration_ms,
        scorecard=scorecard,
    )

    # Store result
    result_dict = result.model_dump()
    _store_scan(result_dict)

    return {"success": True, "data": result_dict}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info",
    )
