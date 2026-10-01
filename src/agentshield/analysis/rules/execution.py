from typing import List

from ...models.finding import SecurityFinding
from ...models.server import MCPServer
from ...models.tool import MCPTool
from ._helpers import mentions_any

APPROVAL_HINTS = ("approval", "confirm", "allowlist", "whitelist", "human_approval", "require_confirmation")


def analyze(tool: MCPTool, server: MCPServer) -> List[SecurityFinding]:
    findings = []
    if "execution" in tool.capabilities and not mentions_any(tool, APPROVAL_HINTS):
        findings.append(
            SecurityFinding(
                severity="critical",
                category="execution",
                tool_name=tool.name,
                server_name=server.name,
                message="Unrestricted shell/subprocess execution with no approval gate detected",
                fix="Add a human-approval hook before execution, or restrict to an allowlist of commands",
                source_file=tool.source_file,
                source_line=tool.source_line,
            )
        )
    return findings
