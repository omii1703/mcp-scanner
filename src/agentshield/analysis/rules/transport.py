from typing import List

from ...models.finding import SecurityFinding
from ...models.server import MCPServer

NETWORK_TRANSPORTS = {"sse", "http"}


def analyze(server: MCPServer) -> List[SecurityFinding]:
    findings = []

    # 1. Missing authentication on network transport
    if server.transport in NETWORK_TRANSPORTS and not server.auth_config:
        findings.append(
            SecurityFinding(
                severity="high",
                category="transport",
                tool_name=None,
                server_name=server.name,
                message=f"Server uses {server.transport.upper()} transport with no authentication configured",
                fix="Add an API key, bearer token, or OAuth check before accepting requests",
                source_file=server.source_file,
                source_line=1,
            )
        )

    # 2. Disabled TLS on network transport (P2 Fix 8)
    # Only fire when tls is explicitly False — tls=None means transport is stdio
    # (a local pipe) where TLS is not a meaningful concept.
    if server.transport in NETWORK_TRANSPORTS and server.tls is False:
        findings.append(
            SecurityFinding(
                severity="medium",
                category="transport",
                tool_name=None,
                server_name=server.name,
                message=f"Server network transport ({server.transport.upper()}) does not use TLS encryption",
                fix="Enable TLS/HTTPS for network transport to protect credentials and data in transit",
                source_file=server.source_file,
                source_line=1,
            )
        )

    # 3. Open binding to 0.0.0.0 (P2 Fix 8)
    if server.host == "0.0.0.0":
        findings.append(
            SecurityFinding(
                severity="high",
                category="transport",
                tool_name=None,
                server_name=server.name,
                message="Server is bound to all network interfaces (0.0.0.0), exposing it beyond localhost",
                fix="Restrict binding host to 127.0.0.1 / localhost unless intentionally exposed with authentication",
                source_file=server.source_file,
                source_line=1,
            )
        )

    return findings
