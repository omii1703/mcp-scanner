from typing import List

from ...models.finding import SecurityFinding
from ...models.server import MCPServer
from ...models.tool import MCPTool
from ._helpers import mentions_any

ALLOWLIST_HINTS = ("allowed_domains", "allowlist", "whitelist", "domain_restriction")


def analyze(tool: MCPTool, server: MCPServer) -> List[SecurityFinding]:
    findings = []
    if "network" in tool.capabilities and not mentions_any(tool, ALLOWLIST_HINTS):
        findings.append(
            SecurityFinding(
                # P7: raised from "medium" — LLM API clients with no allowlist
                # are a genuine exfiltration / data-leak risk.
                severity="high",
                category="network",
                tool_name=tool.name,
                server_name=server.name,
                message="Outbound network/HTTP capability with no domain allowlist detected",
                fix="Add an allowed_domains whitelist to restrict outbound requests",
                source_file=tool.source_file,
                source_line=tool.source_line,
            )
        )
    return findings
