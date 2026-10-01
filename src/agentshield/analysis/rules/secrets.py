import re
from typing import List

from ...models.finding import SecurityFinding

# Matches assignments like: api_key = "sk-..." / API_KEY: "..." / token="..." / secret="..."
_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)\b(api[_-]?key|secret[_-]?key|aws[_-]?secret[_-]?access[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|bearer[_-]?token|token|secret|slack[_-]?webhook|webhook[_-]?url)\b
        \s*[:=]\s*
        ["']([^"'\s]{9,})["']""",
    re.VERBOSE,
)

# High-confidence key-shape regexes independent of variable name
_HIGH_CONFIDENCE_PATTERNS = [
    re.compile(r"""\bsk-[a-zA-Z0-9_-]{20,}\b"""),          # OpenAI key shape (sk-..., sk-proj-..., sk-admin-...)
    re.compile(r"""\bghp_[a-zA-Z0-9]{30,}\b"""),          # GitHub personal access token
    re.compile(r"""\bAKIA[0-9A-Z]{16}\b"""),             # AWS Access Key ID
    re.compile(r"""\bAIza[0-9A-Za-z-_]{35}\b"""),        # Google API Key
    re.compile(r"""\bxox[baprs]-[0-9a-zA-Z_-]{10,}\b"""), # Slack Token / Webhook
    re.compile(r"""https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+\b"""), # Slack Webhook URL
]

_PLACEHOLDER_VALUES = {
    "changeme", "your_api_key", "your-api-key", "xxxxxxxxx", "placeholder",
    "example", "insert_key_here", "todo", "<your_api_key>", "dummy", "test",
    "sample", "your_key_here", "sk-abcdef1234567890", "sk-your-key-here",
}


def analyze_file(file_path: str, source: str, server_name: str = "") -> List[SecurityFinding]:
    findings = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        # 1. Check high-confidence key shape independent of variable name
        high_conf_match = False
        for pattern in _HIGH_CONFIDENCE_PATTERNS:
            m_hc = pattern.search(line)
            if m_hc:
                val = m_hc.group(0)
                if val.lower() not in _PLACEHOLDER_VALUES and "your" not in val.lower():
                    findings.append(
                        SecurityFinding(
                            severity="critical",
                            category="secrets",
                            tool_name=None,
                            server_name=server_name,
                            message=f"Hardcoded credential/API key pattern detected ('{val[:8]}...')",
                            fix="Move to an environment variable or secrets manager (e.g. os.environ['API_KEY'])",
                            source_file=file_path,
                            source_line=lineno,
                        )
                    )
                    high_conf_match = True
                    break

        if high_conf_match:
            continue

        # 2. Check variable assignment pattern
        match = _SECRET_ASSIGNMENT.search(line)
        if not match:
            continue
        value = match.group(2)
        if (
            value.lower() in _PLACEHOLDER_VALUES
            or "dummy" in value.lower()
            or "your" in value.lower()
            or value.upper().startswith("ENV")
            or value.startswith("os.environ")
            or value.startswith("${")
        ):
            continue
        findings.append(
            SecurityFinding(
                severity="critical",
                category="secrets",
                tool_name=None,
                server_name=server_name,
                message=f"Hardcoded credential-like value assigned to '{match.group(1)}'",
                fix="Move to an environment variable or secrets manager (e.g. os.environ['API_KEY'])",
                source_file=file_path,
                source_line=lineno,
            )
        )
    return findings
