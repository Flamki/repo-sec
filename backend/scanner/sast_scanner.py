"""Static Application Security Testing (SAST) engine.

Semgrep-inspired pattern-based code analysis that detects dangerous code
patterns with CWE references. Analyzes source code for injection
vulnerabilities, insecure function calls, weak cryptography, and more.

Unlike regex-only secret scanning, this module understands code context:
- Function calls (eval, exec, os.system)
- String interpolation in dangerous sinks (SQL queries, shell commands)
- Insecure API usage (Math.random for security, MD5 for passwords)
- Framework-specific anti-patterns (dangerouslySetInnerHTML, shell=True)
"""

import re
import uuid
from typing import Dict, List, NamedTuple, Optional, Set
from .models import Finding, FindingType, SeverityLevel


class SASTRule(NamedTuple):
    id: str
    title: str
    description: str
    cwe: str  # CWE identifier
    pattern: re.Pattern
    severity: SeverityLevel
    languages: Set[str]  # file extensions this rule applies to
    confidence: str  # "high", "medium", "low"


# File extension to language mapping
def _exts(*extensions):
    return set(extensions)

JS_TS = _exts(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
PYTHON = _exts(".py")
ALL_CODE = JS_TS | PYTHON | _exts(".rb", ".php", ".java", ".go", ".rs", ".cs")
CONFIG = _exts(".yml", ".yaml")
ALL = ALL_CODE | CONFIG


# ---------------------------------------------------------------------------
# SAST Detection Rules — inspired by OWASP Top 10 / CWE Top 25
# ---------------------------------------------------------------------------

SAST_RULES: List[SASTRule] = [

    # ====================================================================
    # CWE-94: Improper Control of Code Generation (Code Injection)
    # ====================================================================
    SASTRule(
        id="sast-eval-injection",
        title="Dangerous eval() usage — Code Injection",
        description="eval() executes arbitrary code. If user input reaches eval(), attackers can execute any code on the server. Use safe alternatives like JSON.parse() or ast.literal_eval().",
        cwe="CWE-94",
        pattern=re.compile(
            r"""\beval\s*\(\s*(?:"""
            r"""req\.|request\.|params\.|query\.|body\.|input|user|data|"""
            r"""[`'"].*?\$\{|f['"]|['"].*?\+|.*?\.format\()""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.CRITICAL,
        languages=ALL_CODE,
        confidence="high",
    ),
    SASTRule(
        id="sast-eval-usage",
        title="eval() detected — potential Code Injection risk",
        description="eval() can execute arbitrary code. Unless the input is completely trusted and sanitized, this is a security risk. Consider safer alternatives.",
        cwe="CWE-94",
        pattern=re.compile(r"""\beval\s*\("""),
        severity=SeverityLevel.HIGH,
        languages=ALL_CODE,
        confidence="medium",
    ),
    SASTRule(
        id="sast-new-function",
        title="new Function() constructor — Code Injection risk",
        description="The Function constructor creates functions from strings, similar to eval(). Can lead to code injection if input is attacker-controlled.",
        cwe="CWE-94",
        pattern=re.compile(r"""new\s+Function\s*\("""),
        severity=SeverityLevel.HIGH,
        languages=JS_TS,
        confidence="high",
    ),

    # ====================================================================
    # CWE-78: OS Command Injection
    # ====================================================================
    SASTRule(
        id="sast-command-injection-node",
        title="child_process.exec() — Command Injection risk",
        description="exec() runs shell commands. If user input is included without sanitization, attackers can inject arbitrary OS commands. Use execFile() with argument arrays instead.",
        cwe="CWE-78",
        pattern=re.compile(
            r"""(?:child_process|require\s*\(\s*['"]child_process['"]\s*\))"""
            r"""[.\s]*exec\s*\(""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.CRITICAL,
        languages=JS_TS,
        confidence="high",
    ),
    SASTRule(
        id="sast-command-injection-python",
        title="os.system() / subprocess with shell=True — Command Injection",
        description="Running shell commands with os.system() or shell=True allows command injection. Use subprocess with a list of arguments and shell=False.",
        cwe="CWE-78",
        pattern=re.compile(
            r"""(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True)""",
        ),
        severity=SeverityLevel.CRITICAL,
        languages=PYTHON,
        confidence="high",
    ),

    # ====================================================================
    # CWE-89: SQL Injection
    # ====================================================================
    SASTRule(
        id="sast-sql-injection-concat",
        title="SQL query with string concatenation — SQL Injection",
        description="Building SQL queries with string concatenation or template literals allows SQL injection. Use parameterized queries (prepared statements) instead.",
        cwe="CWE-89",
        pattern=re.compile(
            r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\s+"""
            r""".*?(?:\+\s*(?:req|request|params|query|body|input|user|data)"""
            r"""|\$\{(?:req|request|params|query|body|input|user|data)"""
            r"""|['"]?\s*\+\s*\w+\s*\+\s*['"]?\s*(?:WHERE|FROM|INTO|VALUES|SET))""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.CRITICAL,
        languages=ALL_CODE,
        confidence="high",
    ),
    SASTRule(
        id="sast-sql-fstring",
        title="SQL query with f-string/format — SQL Injection risk",
        description="Using f-strings or .format() in SQL queries allows injection. Use parameterized queries with placeholders (?, %s, :param).",
        cwe="CWE-89",
        pattern=re.compile(
            r"""(?:execute|query|raw|cursor\.execute)\s*\(\s*f['"].*?(?:SELECT|INSERT|UPDATE|DELETE)"""
            r"""|(?:execute|query|raw|cursor\.execute)\s*\(\s*['"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\.format\(""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.CRITICAL,
        languages=ALL_CODE,
        confidence="high",
    ),

    # ====================================================================
    # CWE-79: Cross-Site Scripting (XSS)
    # ====================================================================
    SASTRule(
        id="sast-xss-innerhtml",
        title="innerHTML assignment — Cross-Site Scripting (XSS)",
        description="Setting innerHTML with untrusted data allows XSS attacks. Use textContent for text, or sanitize HTML with DOMPurify before insertion.",
        cwe="CWE-79",
        pattern=re.compile(r"""\.innerHTML\s*[=+]"""),
        severity=SeverityLevel.HIGH,
        languages=JS_TS,
        confidence="medium",
    ),
    SASTRule(
        id="sast-xss-document-write",
        title="document.write() — Cross-Site Scripting (XSS)",
        description="document.write() injects raw HTML. If the content includes user input, it enables XSS. Use DOM manipulation methods instead.",
        cwe="CWE-79",
        pattern=re.compile(r"""document\.write(?:ln)?\s*\("""),
        severity=SeverityLevel.HIGH,
        languages=JS_TS,
        confidence="medium",
    ),
    SASTRule(
        id="sast-xss-dangerously",
        title="dangerouslySetInnerHTML — XSS risk in React",
        description="dangerouslySetInnerHTML bypasses React's XSS protections. Ensure the HTML is sanitized with DOMPurify or a similar library before use.",
        cwe="CWE-79",
        pattern=re.compile(r"""dangerouslySetInnerHTML"""),
        severity=SeverityLevel.HIGH,
        languages=JS_TS,
        confidence="high",
    ),

    # ====================================================================
    # CWE-502: Deserialization of Untrusted Data
    # ====================================================================
    SASTRule(
        id="sast-unsafe-deserialization-python",
        title="pickle.loads() — Insecure Deserialization",
        description="pickle can execute arbitrary code during deserialization. Never unpickle data from untrusted sources. Use JSON or protobuf instead.",
        cwe="CWE-502",
        pattern=re.compile(r"""(?:pickle|cPickle|shelve)\.(?:loads?|Unpickler)\s*\("""),
        severity=SeverityLevel.CRITICAL,
        languages=PYTHON,
        confidence="high",
    ),
    SASTRule(
        id="sast-unsafe-deserialization-yaml",
        title="yaml.load() without SafeLoader — Insecure Deserialization",
        description="yaml.load() with the default loader can execute arbitrary Python. Always use yaml.safe_load() or specify Loader=SafeLoader.",
        cwe="CWE-502",
        pattern=re.compile(r"""yaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:Safe|Base)Loader)"""),
        severity=SeverityLevel.HIGH,
        languages=PYTHON,
        confidence="medium",
    ),

    # ====================================================================
    # CWE-327/CWE-328: Weak Cryptography
    # ====================================================================
    SASTRule(
        id="sast-weak-hash",
        title="Weak hash algorithm (MD5/SHA1) — Broken Cryptography",
        description="MD5 and SHA1 are cryptographically broken and should not be used for security purposes (password hashing, integrity checks). Use SHA-256+ or bcrypt/argon2 for passwords.",
        cwe="CWE-328",
        pattern=re.compile(
            r"""(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|"""
            r"""hashlib\.(?:md5|sha1)\s*\(|"""
            r"""MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-1)['"]|"""
            r"""Digest::(?:MD5|SHA1))""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.HIGH,
        languages=ALL_CODE,
        confidence="high",
    ),

    # ====================================================================
    # CWE-330: Insecure Randomness
    # ====================================================================
    SASTRule(
        id="sast-insecure-random",
        title="Math.random() for security — Insecure Randomness",
        description="Math.random() is not cryptographically secure. For tokens, keys, or security-sensitive values, use crypto.randomBytes() or crypto.getRandomValues().",
        cwe="CWE-330",
        pattern=re.compile(
            r"""Math\.random\s*\(\s*\).*?(?:token|secret|key|password|auth|session|csrf|nonce|salt|otp|code)""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.HIGH,
        languages=JS_TS,
        confidence="high",
    ),

    # ====================================================================
    # CWE-22: Path Traversal
    # ====================================================================
    SASTRule(
        id="sast-path-traversal",
        title="Potential Path Traversal — Directory traversal risk",
        description="User input used in file paths without validation can allow attackers to read/write arbitrary files. Validate and sanitize paths, use path.resolve() and check against a base directory.",
        cwe="CWE-22",
        pattern=re.compile(
            r"""(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|"""
            r"""open|access|stat|unlink|rmdir|mkdir)\s*\(\s*(?:"""
            r"""req\.|request\.|params\.|query\.|body\.|input|user_input)""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.HIGH,
        languages=ALL_CODE,
        confidence="medium",
    ),

    # ====================================================================
    # CWE-601: Open Redirect
    # ====================================================================
    SASTRule(
        id="sast-open-redirect",
        title="Potential Open Redirect vulnerability",
        description="Redirecting to a URL from user input without validation allows phishing attacks. Validate redirect URLs against an allowlist of trusted domains.",
        cwe="CWE-601",
        pattern=re.compile(
            r"""(?:res\.redirect|redirect|window\.location|location\.href)\s*"""
            r"""(?:=|\()\s*(?:req\.|request\.|params\.|query\.|body\.)""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.MEDIUM,
        languages=ALL_CODE,
        confidence="medium",
    ),

    # ====================================================================
    # CWE-918: Server-Side Request Forgery (SSRF)
    # ====================================================================
    SASTRule(
        id="sast-ssrf",
        title="Potential SSRF — Server-Side Request Forgery",
        description="Making HTTP requests with user-controlled URLs allows attackers to probe internal services. Validate and restrict URLs to trusted hosts.",
        cwe="CWE-918",
        pattern=re.compile(
            r"""(?:fetch|axios|http\.get|https\.get|request|urllib|requests\.get|httpx\.get)\s*\(\s*"""
            r"""(?:req\.|request\.|params\.|query\.|body\.|input|user)""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.HIGH,
        languages=ALL_CODE,
        confidence="medium",
    ),

    # ====================================================================
    # CWE-1321: Prototype Pollution (JavaScript-specific)
    # ====================================================================
    SASTRule(
        id="sast-prototype-pollution",
        title="Prototype Pollution risk — __proto__ / constructor.prototype",
        description="Accessing __proto__ or constructor.prototype with user input can modify Object.prototype, affecting all objects. Validate property names against a denylist.",
        cwe="CWE-1321",
        pattern=re.compile(
            r"""(?:__proto__|constructor\s*\[\s*['"]prototype['"]\s*\]|Object\.assign\s*\(\s*\{\s*\},\s*(?:req|request|body|params|input))""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.HIGH,
        languages=JS_TS,
        confidence="medium",
    ),

    # ====================================================================
    # GitHub Actions Script Injection (Supply Chain)
    # ====================================================================
    SASTRule(
        id="sast-gha-injection",
        title="GitHub Actions script injection — untrusted input in run:",
        description="Directly interpolating github context (PR titles, issue bodies) into run: commands allows script injection. Pass inputs through env: variables instead.",
        cwe="CWE-78",
        pattern=re.compile(
            r"""\$\{\{\s*github\.event\.(?:pull_request|issue|comment|review|"""
            r"""discussion|head_commit)\.(?:title|body|message|head\.ref)"""
        ),
        severity=SeverityLevel.CRITICAL,
        languages=CONFIG,
        confidence="high",
    ),
    SASTRule(
        id="sast-gha-pull-request-target",
        title="Dangerous pull_request_target trigger with checkout",
        description="pull_request_target with explicit checkout of PR HEAD runs untrusted code with elevated permissions. This is a known 'pwn request' vulnerability.",
        cwe="CWE-829",
        pattern=re.compile(
            r"""pull_request_target.*?(?:ref:\s*\$\{\{|checkout.*?(?:head|ref|sha))""",
            re.IGNORECASE | re.DOTALL
        ),
        severity=SeverityLevel.CRITICAL,
        languages=CONFIG,
        confidence="high",
    ),

    # ====================================================================
    # CWE-532: Information Exposure Through Log Files
    # ====================================================================
    SASTRule(
        id="sast-log-sensitive",
        title="Sensitive data in logs — Information Exposure",
        description="Logging passwords, tokens, or secrets can expose them in log files, monitoring systems, and error reports. Redact sensitive values before logging.",
        cwe="CWE-532",
        pattern=re.compile(
            r"""(?:console\.log|logger?\.\w+|logging\.\w+|print)\s*\(.*?(?:password|secret|token|api_key|apikey|auth|credential|private_key)""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.MEDIUM,
        languages=ALL_CODE,
        confidence="low",
    ),

    # ====================================================================
    # CWE-295: Improper Certificate Validation
    # ====================================================================
    SASTRule(
        id="sast-tls-disabled",
        title="TLS/SSL certificate verification disabled",
        description="Disabling certificate verification makes HTTPS connections vulnerable to man-in-the-middle attacks. Always verify certificates in production.",
        cwe="CWE-295",
        pattern=re.compile(
            r"""(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|"""
            r"""verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|"""
            r"""CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0))""",
            re.IGNORECASE
        ),
        severity=SeverityLevel.HIGH,
        languages=ALL_CODE,
        confidence="high",
    ),

    # ====================================================================
    # CWE-798: Hardcoded IP Addresses
    # ====================================================================
    SASTRule(
        id="sast-hardcoded-ip",
        title="Hardcoded IP address — Configuration anti-pattern",
        description="Hardcoded IPs make infrastructure changes difficult and may expose internal network topology. Use environment variables or DNS names.",
        cwe="CWE-798",
        pattern=re.compile(
            r"""['"](?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})['"]"""
        ),
        severity=SeverityLevel.LOW,
        languages=ALL_CODE,
        confidence="medium",
    ),
]


# ---------------------------------------------------------------------------
# File extension helper
# ---------------------------------------------------------------------------

def _get_ext(filepath: str) -> str:
    """Get file extension (lowercase, with dot)."""
    parts = filepath.rsplit(".", 1)
    if len(parts) == 2:
        return "." + parts[1].lower()
    return ""


# ---------------------------------------------------------------------------
# Main SAST scan function
# ---------------------------------------------------------------------------

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "pipfile.lock", "poetry.lock",
    "cargo.lock", "gemfile.lock", "go.sum",
}

SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "__pycache__", "test", "tests", "spec", "__tests__"}


def scan_sast(files: Dict[str, str]) -> List[Finding]:
    """Run SAST analysis on all source files.

    For each file, determines the language from extension,
    then runs applicable rules with line-by-line matching.
    Returns findings with CWE references and multi-line evidence.
    """
    findings: List[Finding] = []
    seen = set()

    for filepath, content in files.items():
        filename = filepath.split("/")[-1].lower()
        if filename in SKIP_FILES:
            continue

        # Skip test directories for lower false positives
        path_lower = filepath.lower()
        parts = path_lower.split("/")
        if any(d in SKIP_DIRS for d in parts[:-1]):
            continue

        ext = _get_ext(filepath)
        if not ext:
            continue

        lines = content.split("\n")

        for rule in SAST_RULES:
            # Check if this rule applies to this file type
            if ext not in rule.languages:
                continue

            for line_num, line in enumerate(lines, 1):
                if len(line) > 2000:
                    continue

                match = rule.pattern.search(line)
                if not match:
                    continue

                # Deduplicate
                dedup_key = f"{rule.id}:{filepath}:{line_num}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Build multi-line evidence (3 lines of context)
                context_start = max(0, line_num - 2)
                context_end = min(len(lines), line_num + 2)
                evidence_lines = []
                for i in range(context_start, context_end):
                    prefix = ">>>" if i == line_num - 1 else "   "
                    evidence_lines.append(f"{prefix} {i+1}: {lines[i].rstrip()}")
                evidence = "\n".join(evidence_lines)[:500]

                findings.append(Finding(
                    id=f"SAST-{uuid.uuid4().hex[:8].upper()}",
                    type=FindingType.CODE_ISSUE,
                    severity=rule.severity,
                    title=rule.title,
                    description=f"{rule.description} [{rule.cwe}]",
                    file=filepath,
                    line=line_num,
                    evidence=evidence,
                    cwe=rule.cwe,
                ))

    return findings
