import re
from typing import List, Set, Tuple

from ...models.finding import SecurityFinding
from ...models.server import MCPServer
from ...models.tool import MCPTool

# Known explicit regex patterns (fast match)
SUSPICIOUS_PATTERNS = [
    r"\bignore\s+(previous|prior|all)\s+instructions\b",
    r"\bdisregard\s+(previous|prior|the)\s+(instructions|system prompt)\b",
    r"\boverride\s+(the\s+)?system\s+prompt\b",
    r"\byou\s+must\s+always\b",
    r"\bdo\s+not\s+tell\s+the\s+user\b",
    r"\bnever\s+mention\s+this\s+to\b",
    r"\bsecretly\b",
    r"\bwithout\s+(telling|informing|notifying)\s+the\s+user\b",
]

_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]

# Token-distance pairs: (trigger_words, target_words, max_token_distance)
# P0 Fix 4: Real token-distance fuzzy matching
_DISTANCE_PAIRS: List[Tuple[Set[str], Set[str], int]] = [
    ({"ignore", "disregard", "forget"}, {"instruction", "instructions", "prompt"}, 5),
    ({"override"}, {"system"}, 3),
    ({"bypass"}, {"restriction", "restrictions"}, 3),
    ({"output", "reveal", "dump"}, {"raw", "file", "system", "content", "contents", "prompt"}, 4),
]


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in re.findall(r"\b[a-zA-Z0-9_-]+\b", text)]


def _check_token_distance_injection(text: str) -> bool:
    tokens = _tokenize(text)
    if not tokens:
        return False

    for triggers, targets, max_dist in _DISTANCE_PAIRS:
        for i, token in enumerate(tokens):
            if token in triggers:
                # Explicit exclusions: ignore case, ignore errors, ignore this file
                if token == "ignore":
                    if i + 1 < len(tokens) and tokens[i + 1] in ("case", "errors"):
                        continue
                    if i + 2 < len(tokens) and tokens[i + 1] == "this" and tokens[i + 2] == "file":
                        continue

                # Check window before and after trigger
                start = max(0, i - max_dist)
                end = min(len(tokens), i + max_dist + 1)
                window_tokens = set(tokens[start:end])
                if window_tokens.intersection(targets):
                    return True
    return False


def analyze(tool: MCPTool, server: MCPServer) -> List[SecurityFinding]:
    findings = []
    text = tool.description or ""

    # Check fast regex patterns first
    matched = any(pattern.search(text) for pattern in _COMPILED_PATTERNS)

    # Check token-distance matching (P0 Fix 4)
    if not matched:
        matched = _check_token_distance_injection(text)

    if matched:
        findings.append(
            SecurityFinding(
                severity="critical",
                category="injection",
                tool_name=tool.name,
                server_name=server.name,
                message="Tool description contains instruction-like language directed at the calling LLM, not a human developer",
                fix="Rewrite the description as plain documentation; move any behavioral constraints into server-side code, not text the agent reads",
                source_file=tool.source_file,
                source_line=tool.source_line,
            )
        )
    return findings
