"""Pydantic models matching the frontend's expected JSON schema."""

from pydantic import BaseModel
from typing import Optional, List
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


class FindingType(str, Enum):
    SECRET = "SECRET"
    VULNERABILITY = "VULNERABILITY"
    MISCONFIGURATION = "MISCONFIGURATION"


class Finding(BaseModel):
    id: str
    type: FindingType
    severity: SeverityLevel
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    cve: Optional[str] = None


class FixSuggestion(BaseModel):
    findingId: str
    priority: str
    action: str
    detail: str
    resources: List[str] = []


class ScanResult(BaseModel):
    scanId: str
    repoUrl: str
    repoName: str
    severity: SeverityLevel
    findings: List[Finding]
    fixSuggestions: List[FixSuggestion]
    filesScanned: int
    findingsCount: int
    scannedAt: str
    durationMs: int


class ScanRequest(BaseModel):
    repo_url: str
