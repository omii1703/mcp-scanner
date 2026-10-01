from dataclasses import dataclass, field
from typing import Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# OWASP Top 10 for LLM Applications 2025 (v2) — category → standard code mapping.
# Source: https://genai.owasp.org/llm-top-10/
OWASP_MAPPING: dict = {
    "injection": "LLM01: Prompt Injection",
    "llm_code_execution": "LLM02: Insecure Output Handling",
    "execution": "LLM02: Insecure Output Handling",
    "database": "LLM02: Insecure Output Handling",
    "secrets": "LLM06: Sensitive Information Disclosure",
    "network": "LLM06: Sensitive Information Disclosure",
    "filesystem": "LLM06: Sensitive Information Disclosure",
    "transport": "LLM08: Excessive Agency",
    "combined_risk": "LLM08: Excessive Agency",
}


@dataclass
class SecurityFinding:
    severity: str  # "low", "medium", "high", "critical"
    category: str  # "filesystem", "network", "injection", etc.
    server_name: str
    message: str
    fix: str
    source_file: str
    source_line: int
    tool_name: Optional[str] = None
    # Auto-populated from category via OWASP_MAPPING; not a constructor argument.
    owasp_id: Optional[str] = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.owasp_id = OWASP_MAPPING.get(self.category)

    def sort_key(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 4)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "tool_name": self.tool_name,
            "server_name": self.server_name,
            "message": self.message,
            "fix": self.fix,
            "owasp_id": self.owasp_id,
            "source_file": self.source_file,
            "source_line": self.source_line,
        }
