import json
from typing import List

from .. import __version__
from ..models.finding import SecurityFinding
from ..models.server import MCPServer


def build_json_report(servers: List[MCPServer], findings: List[SecurityFinding], overall_score: int) -> dict:
    tool_count = sum(len(s.tools) for s in servers)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "agentshield_version": __version__,
        "overall_score": overall_score,
        "servers_scanned": len(servers),
        "tools_scanned": tool_count,
        "finding_counts": counts,
        "servers": [s.to_dict() for s in servers],
        "findings": [f.to_dict() for f in findings],
    }


def render_json_report(servers: List[MCPServer], findings: List[SecurityFinding], overall_score: int) -> str:
    report = build_json_report(servers, findings, overall_score)
    return json.dumps(report, indent=2)
