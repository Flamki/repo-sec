"""Dependency vulnerability scanner — queries OSV.dev API for known CVEs.

Uses the free, public OSV.dev API (maintained by Google) which aggregates
vulnerability data from GitHub Advisories, PyPA, RustSec, Go Vuln DB, etc.
No API key required.
"""

import re
import json
import uuid
import httpx
from typing import Dict, List, Tuple, Optional
from .models import Finding, FindingType, SeverityLevel


# ---------------------------------------------------------------------------
# Dependency manifest parsers
# ---------------------------------------------------------------------------

def _parse_package_json(content: str) -> List[Tuple[str, str, str]]:
    """Parse package.json → list of (name, version, ecosystem).

    Strips semver range operators (^, ~, >=) to get a concrete version.
    """
    packages = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return packages

    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version_spec in deps.items():
            if not isinstance(version_spec, str):
                continue
            # Strip semver range operators to get base version
            version = re.sub(r"^[~^>=<!\s|]+", "", version_spec).strip()
            # Skip workspace/file/git references
            if not version or version.startswith(("file:", "git", "http", "link:", "*")):
                continue
            # Take first version if OR'd (e.g., "1.0.0 || 2.0.0")
            version = version.split("||")[0].split(" ")[0].strip()
            if re.match(r"^\d+", version):
                packages.append((name, version, "npm"))

    return packages


def _parse_requirements_txt(content: str) -> List[Tuple[str, str, str]]:
    """Parse requirements.txt → list of (name, version, ecosystem)."""
    packages = []
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        # Handle name==version, name>=version, name~=version
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*[=~!><]=?\s*([0-9][^\s;,#]*)", line)
        if match:
            name = match.group(1).lower()
            version = match.group(2).strip().rstrip(",;")
            packages.append((name, version, "PyPI"))
    return packages


def _parse_go_mod(content: str) -> List[Tuple[str, str, str]]:
    """Parse go.mod → list of (name, version, ecosystem)."""
    packages = []
    in_require = False
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if stripped == ")" and in_require:
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            # Lines like: github.com/pkg/errors v0.9.1
            parts = stripped.replace("require ", "").strip().split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].lstrip("v")
                if re.match(r"^\d+\.\d+", version):
                    packages.append((name, version, "Go"))
    return packages


def _parse_gemfile_lock(content: str) -> List[Tuple[str, str, str]]:
    """Parse Gemfile.lock → list of (name, version, ecosystem)."""
    packages = []
    in_specs = False
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs and stripped and not stripped.startswith("("):
            # Lines like: rails (7.0.4)
            match = re.match(r"^([a-zA-Z0-9_-]+)\s+\((\d+[^)]*)\)", stripped)
            if match:
                packages.append((match.group(1), match.group(2), "RubyGems"))
        if stripped in ("", "PLATFORMS", "DEPENDENCIES", "BUNDLED WITH"):
            in_specs = False
    return packages


def _parse_composer_json(content: str) -> List[Tuple[str, str, str]]:
    """Parse composer.json → list of (name, version, ecosystem)."""
    packages = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return packages
    for section in ("require", "require-dev"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version_spec in deps.items():
            if name == "php" or name.startswith("ext-"):
                continue
            version = re.sub(r"^[~^>=<!\s|*]+", "", version_spec).strip()
            if version and re.match(r"^\d+", version):
                packages.append((name, version.split(" ")[0], "Packagist"))
    return packages


# Map of filename → parser function
PARSERS = {
    "package.json": _parse_package_json,
    "requirements.txt": _parse_requirements_txt,
    "go.mod": _parse_go_mod,
    "gemfile.lock": _parse_gemfile_lock,
    "composer.json": _parse_composer_json,
}


def _extract_packages(files: Dict[str, str]) -> List[Tuple[str, str, str, str]]:
    """Extract all dependencies from manifest files.

    Returns list of (name, version, ecosystem, source_file).
    """
    all_packages = []
    for filepath, content in files.items():
        filename = filepath.split("/")[-1].lower()
        parser = PARSERS.get(filename)
        if parser:
            pkgs = parser(content)
            for name, version, ecosystem in pkgs:
                all_packages.append((name, version, ecosystem, filepath))
    return all_packages


# ---------------------------------------------------------------------------
# OSV.dev API integration
# ---------------------------------------------------------------------------

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
BATCH_SIZE = 100  # OSV.dev batch limit


def _severity_from_cvss(score: Optional[float]) -> SeverityLevel:
    """Convert CVSS score to severity level."""
    if score is None:
        return SeverityLevel.MEDIUM
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def _extract_cvss_score(vuln: dict) -> Optional[float]:
    """Extract CVSS score from OSV vulnerability data."""
    severity_list = vuln.get("severity", [])
    for s in severity_list:
        score = s.get("score")
        if score is not None:
            try:
                return float(score)
            except (ValueError, TypeError):
                pass
    # Try database_specific
    db_specific = vuln.get("database_specific", {})
    cvss = db_specific.get("cvss", {})
    if isinstance(cvss, dict):
        score = cvss.get("score")
        if score:
            try:
                return float(score)
            except (ValueError, TypeError):
                pass
    return None


def _extract_cve_id(vuln: dict) -> Optional[str]:
    """Extract CVE ID from OSV vulnerability aliases."""
    aliases = vuln.get("aliases", [])
    for alias in aliases:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    # Sometimes the ID itself is a CVE
    vuln_id = vuln.get("id", "")
    if vuln_id.startswith("CVE-"):
        return vuln_id
    return None


def _extract_fix_version(vuln: dict, pkg_name: str) -> Optional[str]:
    """Extract the fix version from affected ranges."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == pkg_name.lower():
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        return fixed
    return None


async def _fetch_epss_scores(cve_ids: List[str], client: httpx.AsyncClient) -> Dict[str, dict]:
    """Fetch EPSS exploit probability scores from FIRST.org API.

    Returns dict of CVE-ID -> {epss: float, percentile: float}.
    EPSS = probability of exploitation in next 30 days (0-1).
    """
    if not cve_ids:
        return {}

    epss_map = {}
    # EPSS API accepts comma-separated CVEs
    batch_size = 50
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        cve_param = ",".join(batch)
        try:
            resp = await client.get(
                f"https://api.first.org/data/v1/epss?cve={cve_param}",
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                for entry in data:
                    cve = entry.get("cve", "")
                    try:
                        epss_map[cve] = {
                            "epss": float(entry.get("epss", 0)),
                            "percentile": float(entry.get("percentile", 0)),
                        }
                    except (ValueError, TypeError):
                        pass
        except (httpx.HTTPError, httpx.TimeoutException, Exception):
            pass

    return epss_map


async def scan_dependencies(files: Dict[str, str]) -> List[Finding]:
    """Scan dependency manifests for known vulnerabilities via OSV.dev.

    Enriches findings with EPSS exploit probability scores from FIRST.org.
    """
    packages = _extract_packages(files)
    if not packages:
        return []

    findings: List[Finding] = []
    seen = set()

    # Build batch queries
    queries = []
    pkg_map = []  # Track which query maps to which package
    for name, version, ecosystem, source_file in packages:
        queries.append({
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        })
        pkg_map.append((name, version, ecosystem, source_file))

    # Query OSV.dev + EPSS in parallel
    async with httpx.AsyncClient(timeout=20.0) as client:
        # --- Phase 1: OSV.dev batch query ---
        cve_ids_found = []

        for batch_start in range(0, len(queries), BATCH_SIZE):
            batch_queries = queries[batch_start:batch_start + BATCH_SIZE]
            batch_pkgs = pkg_map[batch_start:batch_start + BATCH_SIZE]

            try:
                resp = await client.post(
                    OSV_BATCH_URL,
                    json={"queries": batch_queries},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code != 200:
                    continue
                results = resp.json().get("results", [])
            except (httpx.HTTPError, httpx.TimeoutException, Exception):
                continue

            for i, result in enumerate(results):
                vulns = result.get("vulns", [])
                if not vulns or i >= len(batch_pkgs):
                    continue

                name, version, ecosystem, source_file = batch_pkgs[i]

                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN")
                    dedup_key = f"{vuln_id}:{name}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    cve_id = _extract_cve_id(vuln)
                    cvss_score = _extract_cvss_score(vuln)
                    severity = _severity_from_cvss(cvss_score)
                    fix_version = _extract_fix_version(vuln, name)
                    summary = vuln.get("summary", vuln.get("details", "No description available"))

                    # Truncate summary
                    if len(summary) > 300:
                        summary = summary[:297] + "..."

                    evidence_parts = [f"Package: {name}@{version} ({ecosystem})"]
                    if cve_id:
                        evidence_parts.append(f"CVE: {cve_id}")
                        cve_ids_found.append(cve_id)
                    if cvss_score is not None:
                        evidence_parts.append(f"CVSS: {cvss_score}")
                    if fix_version:
                        evidence_parts.append(f"Fix: upgrade to {fix_version}")

                    findings.append(Finding(
                        id=f"DEP-{uuid.uuid4().hex[:8].upper()}",
                        type=FindingType.VULNERABILITY,
                        severity=severity,
                        title=f"Vulnerable dependency: {name}@{version}",
                        description=summary,
                        file=source_file,
                        line=None,
                        evidence=" | ".join(evidence_parts),
                        cve=cve_id,
                    ))

        # --- Phase 2: EPSS enrichment ---
        if cve_ids_found:
            epss_scores = await _fetch_epss_scores(cve_ids_found, client)

            # Enrich findings with EPSS data
            for finding in findings:
                if finding.cve and finding.cve in epss_scores:
                    epss = epss_scores[finding.cve]
                    prob = epss["epss"]
                    pctl = epss["percentile"]
                    epss_tag = f"EPSS: {prob:.1%} exploit probability (top {pctl:.0%})"
                    finding.evidence = f"{finding.evidence} | {epss_tag}"

                    # Upgrade severity if EPSS is very high
                    if prob > 0.5 and finding.severity == SeverityLevel.MEDIUM:
                        finding.severity = SeverityLevel.HIGH

    return findings

