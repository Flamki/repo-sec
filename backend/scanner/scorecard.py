"""Security Scorecard — OSSF Scorecard-inspired repository health rating.

Evaluates a repository against 10 security checks, each scored 0-10,
using weighted averages with risk-based weights (critical=10, high=7.5,
medium=5, low=2.5). Produces a letter grade (A-F).

Checks inspired by: https://scorecard.dev/
"""

from typing import Dict, List
from .models import ScorecardCheck, SecurityScorecard, Finding


def compute_scorecard(
    files: Dict[str, str],
    tree: List[dict],
    findings: List[Finding],
) -> SecurityScorecard:
    """Compute security scorecard from repo data and scan findings."""
    all_paths = [f["path"].lower() for f in tree]
    all_filenames = [p.split("/")[-1] for p in all_paths]

    checks: List[ScorecardCheck] = []

    # ---- 1. Security Policy (CRITICAL weight) ----
    has_security = any(
        "security" in fn and fn.endswith(".md")
        for fn in all_filenames
    ) or any("security" in p for p in all_paths if ".github/" in p)

    checks.append(ScorecardCheck(
        name="Security-Policy",
        score=10 if has_security else 0,
        maxScore=10,
        reason="SECURITY.md found" if has_security else "No security policy (SECURITY.md) found. Add one to help users report vulnerabilities responsibly.",
        weight="critical",
    ))

    # ---- 2. No Secrets Detected (CRITICAL weight) ----
    secret_count = sum(1 for f in findings if f.type.value == "SECRET")
    sec_score = 10 if secret_count == 0 else max(0, 10 - secret_count * 3)
    checks.append(ScorecardCheck(
        name="No-Secrets",
        score=sec_score,
        maxScore=10,
        reason=f"No hardcoded secrets detected" if secret_count == 0 else f"{secret_count} hardcoded secret(s) detected in source code",
        weight="critical",
    ))

    # ---- 3. No Critical Vulnerabilities (CRITICAL weight) ----
    crit_vulns = sum(1 for f in findings
                     if f.type.value == "VULNERABILITY"
                     and f.severity.value in ("CRITICAL", "HIGH"))
    vuln_score = 10 if crit_vulns == 0 else max(0, 10 - crit_vulns * 2)
    checks.append(ScorecardCheck(
        name="Vulnerability-Free",
        score=vuln_score,
        maxScore=10,
        reason="No critical/high vulnerabilities in dependencies" if crit_vulns == 0 else f"{crit_vulns} critical/high vulnerability(-ies) in dependencies",
        weight="critical",
    ))

    # ---- 4. Dependency Lockfile (HIGH weight) ----
    lockfiles = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                 "pipfile.lock", "poetry.lock", "cargo.lock",
                 "gemfile.lock", "go.sum", "composer.lock"}
    has_lockfile = any(fn in lockfiles for fn in all_filenames)
    checks.append(ScorecardCheck(
        name="Pinned-Dependencies",
        score=10 if has_lockfile else 0,
        maxScore=10,
        reason="Dependency lockfile found (pinned versions)" if has_lockfile else "No dependency lockfile found. Lockfiles prevent supply chain attacks by pinning exact versions.",
        weight="high",
    ))

    # ---- 5. CI/CD Configured (HIGH weight) ----
    has_ci = any(
        ".github/workflows/" in p or
        ".gitlab-ci.yml" in p or
        "jenkinsfile" in fn or
        ".circleci/" in p or
        ".travis.yml" in p
        for p, fn in zip(all_paths, all_filenames)
    )
    checks.append(ScorecardCheck(
        name="CI-Tests",
        score=10 if has_ci else 0,
        maxScore=10,
        reason="CI/CD pipeline configured" if has_ci else "No CI/CD configuration found. Automated testing catches bugs and vulnerabilities before deployment.",
        weight="high",
    ))

    # ---- 6. No Code Issues / SAST Clean (HIGH weight) ----
    code_issues = sum(1 for f in findings if f.type.value == "CODE_ISSUE")
    crit_code = sum(1 for f in findings
                    if f.type.value == "CODE_ISSUE"
                    and f.severity.value in ("CRITICAL", "HIGH"))
    sast_score = 10 if code_issues == 0 else max(0, 10 - crit_code * 3 - (code_issues - crit_code))
    checks.append(ScorecardCheck(
        name="Code-Quality",
        score=max(0, sast_score),
        maxScore=10,
        reason="No dangerous code patterns detected" if code_issues == 0 else f"{code_issues} code issue(s) found ({crit_code} critical/high)",
        weight="high",
    ))

    # ---- 7. .gitignore Present (MEDIUM weight) ----
    has_gitignore = ".gitignore" in all_filenames
    checks.append(ScorecardCheck(
        name="Gitignore",
        score=10 if has_gitignore else 2,
        maxScore=10,
        reason=".gitignore configured" if has_gitignore else "No .gitignore file. Sensitive files may be accidentally committed.",
        weight="medium",
    ))

    # ---- 8. README Present (MEDIUM weight) ----
    has_readme = any(fn.startswith("readme") for fn in all_filenames)
    checks.append(ScorecardCheck(
        name="Documentation",
        score=10 if has_readme else 0,
        maxScore=10,
        reason="README documentation found" if has_readme else "No README file found. Documentation helps users understand the project's security posture.",
        weight="medium",
    ))

    # ---- 9. LICENSE Present (MEDIUM weight) ----
    has_license = any(
        fn in ("license", "license.md", "license.txt", "licence", "copying")
        for fn in all_filenames
    )
    checks.append(ScorecardCheck(
        name="License",
        score=10 if has_license else 0,
        maxScore=10,
        reason="License file found" if has_license else "No license file. Without a license, the code is 'all rights reserved' by default.",
        weight="medium",
    ))

    # ---- 10. No Misconfigurations (LOW weight) ----
    misconfig_count = sum(1 for f in findings if f.type.value == "MISCONFIGURATION")
    crit_misconfig = sum(1 for f in findings
                        if f.type.value == "MISCONFIGURATION"
                        and f.severity.value == "CRITICAL")
    misconfig_score = 10 if misconfig_count == 0 else max(0, 10 - crit_misconfig * 4 - misconfig_count)
    checks.append(ScorecardCheck(
        name="Secure-Config",
        score=max(0, misconfig_score),
        maxScore=10,
        reason="No misconfigurations detected" if misconfig_count == 0 else f"{misconfig_count} misconfiguration(s) found ({crit_misconfig} critical)",
        weight="low",
    ))

    # ---- Calculate weighted average ----
    weight_values = {"critical": 10, "high": 7.5, "medium": 5, "low": 2.5}
    total_weighted = sum(c.score * weight_values[c.weight] for c in checks)
    total_weight = sum(weight_values[c.weight] for c in checks)
    overall = round(total_weighted / total_weight, 1) if total_weight > 0 else 0

    # ---- Letter grade ----
    if overall >= 8.5:
        grade = "A"
    elif overall >= 7.0:
        grade = "B"
    elif overall >= 5.0:
        grade = "C"
    elif overall >= 3.0:
        grade = "D"
    else:
        grade = "F"

    return SecurityScorecard(
        overallScore=overall,
        checks=checks,
        grade=grade,
    )
