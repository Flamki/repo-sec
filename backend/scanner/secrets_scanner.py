"""Secrets detection engine — regex patterns + Shannon entropy analysis.

Patterns are based on publicly documented API key formats from each provider's
official documentation (AWS IAM docs, GitHub token docs, Stripe API docs, etc.).
"""

import re
import math
import uuid
from typing import Dict, List, NamedTuple, Optional
from .models import Finding, FindingType, SeverityLevel


class SecretRule(NamedTuple):
    id: str
    title: str
    description: str
    pattern: re.Pattern
    severity: SeverityLevel
    keywords: List[str]  # Fast pre-filter before regex
    entropy_threshold: float  # 0 = no entropy check


def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Detection rules — based on publicly documented key prefixes/formats
# ---------------------------------------------------------------------------
RULES: List[SecretRule] = [
    # ---- Cloud Providers ----
    SecretRule(
        id="aws-access-key",
        title="AWS Access Key ID",
        description="AWS access key IDs start with AKIA/ASIA prefix (documented in AWS IAM docs). Exposed keys can grant full AWS account access.",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b"),
        severity=SeverityLevel.CRITICAL,
        keywords=["akia", "asia", "abia", "acca"],
        entropy_threshold=3.0,
    ),
    SecretRule(
        id="aws-secret-key",
        title="AWS Secret Access Key",
        description="Potential AWS secret key found near an AWS-related keyword. Secret keys are 40-character base64 strings.",
        pattern=_compile(
            r"(?:aws.{0,20}(?:secret|key|token|credential))[^a-zA-Z0-9]*['\"\s=:]+\s*([a-zA-Z0-9/+=]{40})"
        ),
        severity=SeverityLevel.CRITICAL,
        keywords=["aws"],
        entropy_threshold=4.0,
    ),
    SecretRule(
        id="gcp-api-key",
        title="Google Cloud API Key",
        description="Google API keys begin with AIza prefix (documented in Google Cloud docs). Can grant access to GCP services.",
        pattern=re.compile(r"\b(AIza[a-zA-Z0-9_-]{35})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["aiza"],
        entropy_threshold=3.5,
    ),
    SecretRule(
        id="azure-client-secret",
        title="Azure AD Client Secret",
        description="Pattern matching Azure AD client secrets (contains Q~ marker per Azure docs).",
        pattern=re.compile(r"[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}"),
        severity=SeverityLevel.CRITICAL,
        keywords=["q~"],
        entropy_threshold=3.0,
    ),

    # ---- Source Code Platforms ----
    SecretRule(
        id="github-pat",
        title="GitHub Personal Access Token",
        description="GitHub PATs use ghp_ prefix (documented in GitHub token docs). Grants repository and API access.",
        pattern=re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b"),
        severity=SeverityLevel.CRITICAL,
        keywords=["ghp_"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="github-oauth",
        title="GitHub OAuth Access Token",
        description="GitHub OAuth tokens use gho_ prefix. Can access user data and repositories.",
        pattern=re.compile(r"\b(gho_[a-zA-Z0-9]{36})\b"),
        severity=SeverityLevel.CRITICAL,
        keywords=["gho_"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="github-app-token",
        title="GitHub App Installation Token",
        description="GitHub App tokens use ghs_ prefix. Grants app-level API access.",
        pattern=re.compile(r"\b(ghs_[a-zA-Z0-9]{36})\b"),
        severity=SeverityLevel.CRITICAL,
        keywords=["ghs_"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="github-fine-grained",
        title="GitHub Fine-Grained PAT",
        description="GitHub fine-grained PATs use github_pat_ prefix with scoped permissions.",
        pattern=re.compile(r"\b(github_pat_[a-zA-Z0-9_]{22,82})\b"),
        severity=SeverityLevel.CRITICAL,
        keywords=["github_pat_"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="gitlab-pat",
        title="GitLab Personal Access Token",
        description="GitLab PATs use glpat- prefix (documented in GitLab docs).",
        pattern=re.compile(r"\b(glpat-[a-zA-Z0-9_-]{20,})\b"),
        severity=SeverityLevel.CRITICAL,
        keywords=["glpat-"],
        entropy_threshold=0,
    ),

    # ---- Payment / Finance ----
    SecretRule(
        id="stripe-secret-key",
        title="Stripe Secret Key",
        description="Stripe secret keys use sk_live_ or sk_test_ prefix (documented in Stripe API docs). Grants payment processing access.",
        pattern=re.compile(r"\b((?:sk_live|sk_test)_[a-zA-Z0-9]{24,})\b"),
        severity=SeverityLevel.CRITICAL,
        keywords=["sk_live", "sk_test"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="stripe-publishable-key",
        title="Stripe Publishable Key",
        description="Stripe publishable keys use pk_live_ or pk_test_ prefix. Lower risk but should not be in server-side code.",
        pattern=re.compile(r"\b((?:pk_live|pk_test)_[a-zA-Z0-9]{24,})\b"),
        severity=SeverityLevel.LOW,
        keywords=["pk_live", "pk_test"],
        entropy_threshold=0,
    ),

    # ---- Communication Platforms ----
    SecretRule(
        id="slack-bot-token",
        title="Slack Bot Token",
        description="Slack bot tokens use xoxb- prefix (documented in Slack API docs). Grants bot-level workspace access.",
        pattern=re.compile(r"\b(xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["xoxb-"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="slack-user-token",
        title="Slack User Token",
        description="Slack user tokens use xoxp- prefix. Grants user-level workspace access.",
        pattern=re.compile(r"\b(xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})\b"),
        severity=SeverityLevel.CRITICAL,
        keywords=["xoxp-"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="slack-webhook",
        title="Slack Incoming Webhook URL",
        description="Slack webhook URLs allow posting messages to channels without authentication.",
        pattern=_compile(r"(https?://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+)"),
        severity=SeverityLevel.MEDIUM,
        keywords=["hooks.slack.com"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="discord-bot-token",
        title="Discord Bot Token",
        description="Discord bot tokens are base64-encoded and grant full bot access to servers.",
        pattern=_compile(r"(?:discord|bot).{0,30}['\"\s=:]+\s*([a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,})"),
        severity=SeverityLevel.HIGH,
        keywords=["discord"],
        entropy_threshold=3.5,
    ),
    SecretRule(
        id="telegram-bot-token",
        title="Telegram Bot Token",
        description="Telegram bot tokens follow a numeric:alphanumeric pattern per Telegram Bot API docs.",
        pattern=re.compile(r"\b(\d{8,10}:[a-zA-Z0-9_-]{35})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["telegram", "bot"],
        entropy_threshold=3.0,
    ),

    # ---- AI / ML Platforms ----
    SecretRule(
        id="openai-api-key",
        title="OpenAI API Key",
        description="OpenAI API keys use sk-proj- or sk- prefix (documented in OpenAI docs). Grants access to GPT and other models.",
        pattern=re.compile(r"\b(sk-(?:proj-)?[a-zA-Z0-9]{32,})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["sk-"],
        entropy_threshold=3.5,
    ),
    SecretRule(
        id="anthropic-api-key",
        title="Anthropic API Key",
        description="Anthropic API keys use sk-ant- prefix. Grants access to Claude models.",
        pattern=re.compile(r"\b(sk-ant-(?:api03|admin01)-[a-zA-Z0-9_-]{80,})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["sk-ant-"],
        entropy_threshold=0,
    ),

    # ---- Package Registries ----
    SecretRule(
        id="npm-access-token",
        title="npm Access Token",
        description="npm tokens use npm_ prefix (documented in npm docs). Grants package publish access.",
        pattern=re.compile(r"\b(npm_[a-zA-Z0-9]{36})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["npm_"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="pypi-api-token",
        title="PyPI API Token",
        description="PyPI tokens use pypi- prefix (documented in PyPI docs). Grants package upload access.",
        pattern=re.compile(r"\b(pypi-[a-zA-Z0-9_-]{100,})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["pypi-"],
        entropy_threshold=0,
    ),

    # ---- Email / Messaging Services ----
    SecretRule(
        id="sendgrid-api-key",
        title="SendGrid API Key",
        description="SendGrid keys use SG. prefix (documented in SendGrid docs). Grants email sending access.",
        pattern=re.compile(r"\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["sg."],
        entropy_threshold=0,
    ),
    SecretRule(
        id="mailgun-api-key",
        title="Mailgun API Key",
        description="Potential Mailgun API key detected near mailgun keyword.",
        pattern=_compile(r"(?:mailgun).{0,20}(?:key|api|secret|token)[^a-zA-Z0-9]*['\"\s=:]+\s*([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})"),
        severity=SeverityLevel.HIGH,
        keywords=["mailgun"],
        entropy_threshold=3.0,
    ),
    SecretRule(
        id="twilio-api-key",
        title="Twilio API Key",
        description="Twilio API keys use SK prefix followed by 32 hex characters (documented in Twilio docs).",
        pattern=re.compile(r"\b(SK[a-f0-9]{32})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["twilio", "sk"],
        entropy_threshold=3.5,
    ),

    # ---- Infrastructure ----
    SecretRule(
        id="digitalocean-pat",
        title="DigitalOcean Personal Access Token",
        description="DigitalOcean PATs use dop_v1_ prefix (documented in DO API docs).",
        pattern=re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["dop_v1_"],
        entropy_threshold=0,
    ),
    SecretRule(
        id="heroku-api-key",
        title="Heroku API Key",
        description="Potential Heroku API key detected near heroku keyword.",
        pattern=_compile(r"(?:heroku).{0,20}(?:key|api|token)[^a-zA-Z0-9]*['\"\s=:]+\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"),
        severity=SeverityLevel.HIGH,
        keywords=["heroku"],
        entropy_threshold=0,
    ),

    # ---- E-Commerce ----
    SecretRule(
        id="shopify-access-token",
        title="Shopify Access Token",
        description="Shopify tokens use shpat_ prefix (documented in Shopify API docs).",
        pattern=re.compile(r"\b(shpat_[a-f0-9]{32})\b"),
        severity=SeverityLevel.HIGH,
        keywords=["shpat_"],
        entropy_threshold=0,
    ),

    # ---- Cryptographic Material ----
    SecretRule(
        id="private-key",
        title="Private Key (PEM Format)",
        description="PEM-encoded private key detected. Private keys must never be committed to version control.",
        pattern=re.compile(r"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:\s+BLOCK)?-----"),
        severity=SeverityLevel.CRITICAL,
        keywords=["-----begin", "private key"],
        entropy_threshold=0,
    ),

    # ---- Authentication Tokens ----
    SecretRule(
        id="jwt-token",
        title="JSON Web Token (JWT)",
        description="Hardcoded JWT detected. JWTs should be dynamically generated and never stored in source code.",
        pattern=re.compile(r"\b(eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})\b"),
        severity=SeverityLevel.MEDIUM,
        keywords=["eyj"],
        entropy_threshold=3.5,
    ),

    # ---- Database Credentials ----
    SecretRule(
        id="database-url",
        title="Database Connection String with Credentials",
        description="Database connection URI with embedded credentials detected. Use environment variables instead.",
        pattern=_compile(
            r"((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^:\s]+:[^@\s]+@[^\s'\"]+)"
        ),
        severity=SeverityLevel.CRITICAL,
        keywords=["mongodb://", "postgres://", "postgresql://", "mysql://", "redis://", "amqp://", "mssql://"],
        entropy_threshold=0,
    ),

    # ---- Generic High-Entropy Secrets ----
    SecretRule(
        id="generic-api-key",
        title="Generic API Key / Secret",
        description="High-entropy string assigned to a variable with a secret-related name. Review and externalize to environment variables.",
        pattern=_compile(
            r"(?:api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)"
            r"\s*[=:]\s*['\"]([a-zA-Z0-9/+=_-]{16,})['\"]"
        ),
        severity=SeverityLevel.HIGH,
        keywords=["api_key", "api-key", "apisecret", "api_secret", "access_key", "secret_key",
                  "auth_token", "access_token", "apikey"],
        entropy_threshold=3.5,
    ),
    SecretRule(
        id="generic-password",
        title="Hardcoded Password",
        description="Password or secret value hardcoded in source code. Use environment variables or a secrets manager.",
        pattern=_compile(
            r"(?:password|passwd|pwd|secret)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]"
        ),
        severity=SeverityLevel.HIGH,
        keywords=["password", "passwd", "pwd", "secret"],
        entropy_threshold=3.0,
    ),
]


# ---------------------------------------------------------------------------
# Shannon entropy calculation
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string.

    Higher entropy = more random = more likely to be a real secret.
    Typical thresholds: >3.5 for hex strings, >4.0 for base64.
    """
    if not data:
        return 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Redaction helper
# ---------------------------------------------------------------------------

def _redact(value: str, show_chars: int = 6) -> str:
    """Redact a secret value, showing only the first few characters."""
    if len(value) <= show_chars:
        return "*" * len(value)
    return value[:show_chars] + "*" * min(len(value) - show_chars, 20)


# ---------------------------------------------------------------------------
# Main scanning function
# ---------------------------------------------------------------------------

# Files to never scan for secrets (false positive magnets)
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "pipfile.lock", "poetry.lock",
    "cargo.lock", "gemfile.lock", "go.sum",
}


def scan_secrets(files: Dict[str, str]) -> List[Finding]:
    """Scan all file contents for hardcoded secrets.

    Uses keyword pre-filtering + regex matching + entropy validation.
    """
    findings: List[Finding] = []
    seen_hashes = set()  # Deduplicate

    for filepath, content in files.items():
        filename = filepath.split("/")[-1].lower()
        if filename in SKIP_FILES:
            continue

        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            line_lower = line.lower()
            if len(line) > 2000:
                # Skip extremely long lines (likely minified)
                continue

            for rule in RULES:
                # 1. Quick keyword pre-filter
                if not any(kw in line_lower for kw in rule.keywords):
                    continue

                # 2. Regex match
                match = rule.pattern.search(line)
                if not match:
                    continue

                # Extract the captured group (secret value) or full match
                secret_value = match.group(1) if match.lastindex else match.group(0)

                # 3. Entropy check (if threshold > 0)
                if rule.entropy_threshold > 0:
                    ent = shannon_entropy(secret_value)
                    if ent < rule.entropy_threshold:
                        continue

                # 4. Deduplicate
                dedup_key = f"{rule.id}:{filepath}:{secret_value[:20]}"
                if dedup_key in seen_hashes:
                    continue
                seen_hashes.add(dedup_key)

                # 5. Build evidence with redacted secret
                evidence_line = line.strip()
                try:
                    evidence_line = evidence_line.replace(
                        secret_value, _redact(secret_value)
                    )
                except Exception:
                    evidence_line = evidence_line[:80] + "..."

                findings.append(Finding(
                    id=f"SEC-{uuid.uuid4().hex[:8].upper()}",
                    type=FindingType.SECRET,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    file=filepath,
                    line=line_num,
                    evidence=evidence_line[:300],
                ))

    return findings
