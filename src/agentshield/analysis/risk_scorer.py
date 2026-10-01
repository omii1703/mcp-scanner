from typing import List

from ..models.finding import SecurityFinding
from ..models.server import MCPServer

# Multiplicative (not linear) penalty per finding, applied per severity
# bucket: score *= factor ** count. This gives diminishing returns instead
# of a flat subtraction — a server with 5 critical findings still scores
# very low, but doesn't hit a hard 0 the moment findings start overlapping
# (which happens often here, since one root cause like "no sandboxing" can
# trigger both an individual rule and the combined-risk rule).
_PENALTY_FACTOR = {"critical": 0.72, "high": 0.85, "medium": 0.93, "low": 0.98}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def compute_confidence_penalty(servers: List[MCPServer]) -> int:
    """P8: Return a confidence penalty (0–25) reflecting how incomplete the
    scanner's analysis was.

    Contributors:
    +5  — any server with transport == "unknown"  (couldn't determine exposure)
    +5  — any server where >50 % of tools have empty descriptions
           (schema-only tools: capabilities may be under-detected)
    +5  — any tool that had unresolvable imports during call-graph tracing
           (transitive capabilities were only partially explored)

    Total is capped at 25 so it can never bring a perfect-server score
    below 75 — the penalty should reflect uncertainty, not fabricate findings.
    """
    penalty = 0

    for server in servers:
        # Unknown transport means we can't evaluate exposure
        if server.transport == "unknown":
            penalty += 5
            break  # one penalty per project is enough signal

    for server in servers:
        if not server.tools:
            continue
        empty_desc = sum(1 for t in server.tools if not (t.description or "").strip())
        if empty_desc / len(server.tools) > 0.5:
            penalty += 5
            break  # one penalty is enough

    for server in servers:
        if any(t.unresolved_imports for t in server.tools):
            penalty += 5
            break  # one penalty is enough

    return min(penalty, 25)


def compute_overall_score(servers: List[MCPServer], findings: List[SecurityFinding]) -> int:
    """Compute a 0–100 security score.

    Base score is multiplicatively reduced by finding counts per severity,
    then further reduced by a confidence penalty (P8) that reflects how
    much of the codebase the scanner could not fully analyse.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    score = 100.0
    for severity, count in counts.items():
        score *= _PENALTY_FACTOR.get(severity, 1.0) ** count

    # P8: subtract confidence penalty for incomplete analysis
    confidence_penalty = compute_confidence_penalty(servers)
    score = max(0.0, score - confidence_penalty)

    return max(0, round(score))


def apply_tool_risk_scores(servers: List[MCPServer], findings: List[SecurityFinding]) -> None:
    """Mutates each tool's risk_score in place to reflect the worst finding
    that references it."""
    worst_by_tool = {}
    for finding in findings:
        if finding.tool_name is None:
            continue
        key = (finding.server_name, finding.tool_name)
        rank = _SEVERITY_RANK.get(finding.severity, 4)
        if key not in worst_by_tool or rank < worst_by_tool[key]:
            worst_by_tool[key] = rank

    rank_to_severity = {v: k for k, v in _SEVERITY_RANK.items()}
    for server in servers:
        for tool in server.tools:
            key = (server.name, tool.name)
            if key in worst_by_tool:
                tool.risk_score = rank_to_severity[worst_by_tool[key]]
            else:
                tool.risk_score = "low"
