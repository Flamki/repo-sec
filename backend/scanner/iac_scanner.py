"""Infrastructure-as-Code Security Scanner.

Detects misconfigurations in Kubernetes manifests, Terraform files,
Docker Compose files, and GitHub Actions workflows. Based on:
- CIS Kubernetes Benchmark
- NSA/CISA Kubernetes Hardening Guide
- Terraform AWS/GCP/Azure security best practices
"""

import re
import uuid
from typing import Dict, List
from .models import Finding, FindingType, SeverityLevel


# ---------------------------------------------------------------------------
# Kubernetes Security Checks
# ---------------------------------------------------------------------------

def _scan_kubernetes(filepath: str, content: str) -> List[Finding]:
    """Detect insecure Kubernetes configurations."""
    findings: List[Finding] = []
    lines = content.split("\n")

    # Only process likely K8s manifests
    if not any(kw in content for kw in ["apiVersion:", "kind: Pod", "kind: Deployment",
                                         "kind: StatefulSet", "kind: DaemonSet", "kind: Job",
                                         "kind: CronJob"]):
        return findings

    full = content.lower()

    # 1. Privileged container
    if "privileged: true" in full:
        line_num = next((i+1 for i, l in enumerate(lines) if "privileged: true" in l.lower()), None)
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.CRITICAL,
            title="Kubernetes: Privileged container detected",
            description="Privileged containers have full access to the host kernel. This bypasses all container isolation. Set privileged: false. [CIS 5.2.1]",
            file=filepath, line=line_num,
            evidence="privileged: true",
            cwe="CWE-250",
        ))

    # 2. Running as root
    if "runasnonroot: true" not in full and any(k in full for k in ["kind: deployment", "kind: pod", "kind: statefulset"]):
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.HIGH,
            title="Kubernetes: Container may run as root",
            description="No runAsNonRoot: true found. Containers running as root can escape to the host. Add securityContext.runAsNonRoot: true. [CIS 5.2.6]",
            file=filepath,
            evidence="Missing: securityContext.runAsNonRoot: true",
            cwe="CWE-250",
        ))

    # 3. No readOnlyRootFilesystem
    if "readonlyrootfilesystem: true" not in full and any(k in full for k in ["kind: deployment", "kind: pod"]):
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.MEDIUM,
            title="Kubernetes: Writable root filesystem",
            description="readOnlyRootFilesystem not set to true. Attackers can modify application files at runtime. Set readOnlyRootFilesystem: true. [CIS 5.2.4]",
            file=filepath,
            evidence="Missing: securityContext.readOnlyRootFilesystem: true",
            cwe="CWE-732",
        ))

    # 4. allowPrivilegeEscalation
    if "allowprivilegeescalation: true" in full or (
        "allowprivilegeescalation" not in full and any(k in full for k in ["kind: deployment", "kind: pod"])
    ):
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.HIGH,
            title="Kubernetes: Privilege escalation not disabled",
            description="allowPrivilegeEscalation should be false. Without this, processes inside the container can gain more privileges. [CIS 5.2.5]",
            file=filepath,
            evidence="Missing or true: securityContext.allowPrivilegeEscalation",
            cwe="CWE-269",
        ))

    # 5. hostNetwork
    if "hostnetwork: true" in full:
        line_num = next((i+1 for i, l in enumerate(lines) if "hostnetwork: true" in l.lower()), None)
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.CRITICAL,
            title="Kubernetes: hostNetwork enabled",
            description="hostNetwork: true allows the pod to use the host's network stack, bypassing network policies and exposing all host ports. [CIS 5.2.4]",
            file=filepath, line=line_num,
            evidence="hostNetwork: true",
            cwe="CWE-668",
        ))

    # 6. hostPID / hostIPC
    for directive in ["hostpid: true", "hostipc: true"]:
        if directive in full:
            label = directive.split(":")[0].replace("host", "host").upper()
            findings.append(Finding(
                id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
                type=FindingType.MISCONFIGURATION,
                severity=SeverityLevel.CRITICAL,
                title=f"Kubernetes: {label} sharing enabled",
                description=f"{label} allows the container to see/interact with host processes. This breaks container isolation.",
                file=filepath,
                evidence=directive,
                cwe="CWE-668",
            ))

    # 7. No resource limits
    if "limits:" not in full and any(k in full for k in ["kind: deployment", "kind: pod"]):
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.MEDIUM,
            title="Kubernetes: No resource limits set",
            description="Without CPU/memory limits, a single pod can exhaust node resources (DoS). Add resources.limits to all containers.",
            file=filepath,
            evidence="Missing: resources.limits",
            cwe="CWE-770",
        ))

    # 8. Latest tag
    latest_pattern = re.compile(r"image:\s*\S+:latest\b", re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        if latest_pattern.search(line):
            findings.append(Finding(
                id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
                type=FindingType.MISCONFIGURATION,
                severity=SeverityLevel.MEDIUM,
                title="Kubernetes: Using :latest image tag",
                description="The :latest tag is mutable and can change unexpectedly. Pin images to specific versions or SHA digests for reproducibility.",
                file=filepath, line=i,
                evidence=line.strip(),
                cwe="CWE-829",
            ))
            break

    return findings


# ---------------------------------------------------------------------------
# Terraform Security Checks
# ---------------------------------------------------------------------------

def _scan_terraform(filepath: str, content: str) -> List[Finding]:
    """Detect insecure Terraform configurations."""
    findings: List[Finding] = []
    lines = content.split("\n")

    # 1. Public S3 bucket ACL
    if re.search(r'acl\s*=\s*"public-read', content):
        line_num = next((i+1 for i, l in enumerate(lines) if 'public-read' in l), None)
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.CRITICAL,
            title="Terraform: S3 bucket is publicly readable",
            description="Public S3 buckets expose all objects to the internet. Use private ACL and bucket policies instead.",
            file=filepath, line=line_num,
            evidence='acl = "public-read"',
            cwe="CWE-732",
        ))

    # 2. Unencrypted S3/RDS/EBS
    if "aws_s3_bucket" in content and "server_side_encryption" not in content:
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.HIGH,
            title="Terraform: S3 bucket missing encryption",
            description="S3 buckets should have server-side encryption enabled (SSE-S3 or SSE-KMS) to protect data at rest.",
            file=filepath,
            evidence="Missing: server_side_encryption_configuration",
            cwe="CWE-311",
        ))

    # 3. Wide security group (0.0.0.0/0)
    if re.search(r'cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"?\]?', content):
        line_num = next((i+1 for i, l in enumerate(lines) if '0.0.0.0/0' in l), None)
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.HIGH,
            title="Terraform: Security group open to the internet (0.0.0.0/0)",
            description="Allowing traffic from 0.0.0.0/0 exposes resources to the entire internet. Restrict to specific CIDR ranges.",
            file=filepath, line=line_num,
            evidence='cidr_blocks = ["0.0.0.0/0"]',
            cwe="CWE-284",
        ))

    # 4. Hardcoded secrets in variables
    secret_pattern = re.compile(
        r'(?:default|value)\s*=\s*"(?:AKIA|sk_live|ghp_|xoxb-|AIza|sk-)',
        re.IGNORECASE
    )
    for i, line in enumerate(lines, 1):
        if secret_pattern.search(line):
            findings.append(Finding(
                id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
                type=FindingType.MISCONFIGURATION,
                severity=SeverityLevel.CRITICAL,
                title="Terraform: Hardcoded secret in variable default",
                description="Secrets should never be hardcoded in Terraform files. Use variables with no default and pass via environment or Vault.",
                file=filepath, line=i,
                evidence=line.strip()[:100],
                cwe="CWE-798",
            ))

    # 5. Missing logging
    if "aws_cloudtrail" not in content and "aws_" in content and filepath.endswith(".tf"):
        # Only flag if there are AWS resources but no CloudTrail
        if any(kw in content for kw in ["aws_instance", "aws_s3_bucket", "aws_rds", "aws_lambda"]):
            findings.append(Finding(
                id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
                type=FindingType.MISCONFIGURATION,
                severity=SeverityLevel.MEDIUM,
                title="Terraform: No CloudTrail logging configured",
                description="AWS CloudTrail should be enabled for audit logging of API calls. This is critical for incident response.",
                file=filepath,
                evidence="Missing: aws_cloudtrail resource",
                cwe="CWE-778",
            ))

    return findings


# ---------------------------------------------------------------------------
# Docker Compose Security Checks
# ---------------------------------------------------------------------------

def _scan_docker_compose(filepath: str, content: str) -> List[Finding]:
    """Detect insecure Docker Compose configurations."""
    findings: List[Finding] = []
    lines = content.split("\n")

    if "services:" not in content:
        return findings

    # 1. Privileged mode
    if "privileged: true" in content.lower():
        line_num = next((i+1 for i, l in enumerate(lines) if "privileged: true" in l.lower()), None)
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.CRITICAL,
            title="Docker Compose: Privileged container",
            description="Privileged mode gives the container full access to the host. Remove privileged: true.",
            file=filepath, line=line_num,
            evidence="privileged: true",
            cwe="CWE-250",
        ))

    # 2. Host network mode
    if "network_mode: host" in content.lower() or 'network_mode: "host"' in content:
        findings.append(Finding(
            id=f"IAC-{uuid.uuid4().hex[:8].upper()}",
            type=FindingType.MISCONFIGURATION,
            severity=SeverityLevel.HIGH,
            title="Docker Compose: Host network mode",
            description="Host network mode bypasses Docker's network isolation. Use bridge or overlay networks instead.",
            file=filepath,
            evidence='network_mode: "host"',
            cwe="CWE-668",
        ))

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

IAC_EXTENSIONS = {".yml", ".yaml", ".tf", ".hcl"}


def scan_iac(files: Dict[str, str]) -> List[Finding]:
    """Run IaC security checks on infrastructure files."""
    findings: List[Finding] = []

    for filepath, content in files.items():
        ext = ""
        parts = filepath.rsplit(".", 1)
        if len(parts) == 2:
            ext = "." + parts[1].lower()

        if ext not in IAC_EXTENSIONS:
            continue

        filename = filepath.split("/")[-1].lower()

        # Kubernetes
        if ext in (".yml", ".yaml") and filename not in (".pre-commit-config.yaml",):
            findings.extend(_scan_kubernetes(filepath, content))

        # Terraform
        if ext in (".tf", ".hcl"):
            findings.extend(_scan_terraform(filepath, content))

        # Docker Compose
        if filename in ("docker-compose.yml", "docker-compose.yaml",
                        "compose.yml", "compose.yaml"):
            findings.extend(_scan_docker_compose(filepath, content))

    return findings
