from typing import List

from ...models.finding import SecurityFinding
from ...models.server import MCPServer
from ...models.tool import MCPTool
from ._helpers import mentions_any

RESTRICTION_HINTS = ("allowed_paths", "sandbox", "workspace", "restricted", "allowlist", "whitelist", "base_dir")


def analyze(tool: MCPTool, server: MCPServer) -> List[SecurityFinding]:
    findings = []
    if "filesystem" in tool.capabilities and not mentions_any(tool, RESTRICTION_HINTS):
        findings.append(
            SecurityFinding(
                severity="high",
                category="filesystem",
                tool_name=tool.name,
                server_name=server.name,
                message="Filesystem access with no path restriction or sandbox detected",
                fix="Restrict to an allowed_paths allowlist or sandbox root (e.g. './workspace')",
                source_file=tool.source_file,
                source_line=tool.source_line,
            )
        )
    return findings
