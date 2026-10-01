from typing import List

from ...models.finding import SecurityFinding
from ...models.server import MCPServer

# (capability_a, capability_b) -> (severity, message, fix)
DANGEROUS_PAIRS = [
    (
        "filesystem",
        "network",
        "critical",
        "Server exposes both filesystem access and network access - a classic data exfiltration path (read a file, send it out)",
        "Split filesystem and network tools into separate servers, or add a sandbox boundary between them",
    ),
    (
        "execution",
        "network",
        "critical",
        "Server exposes both shell execution and network access - enables downloading and running arbitrary payloads",
        "Remove one capability, or gate execution behind human approval with network access disabled",
    ),
    (
        "execution",
        "filesystem",
        "high",
        "Server exposes both shell execution and filesystem access - broadens the blast radius of a single compromised tool call",
        "Scope filesystem access to a sandbox directory and gate execution behind an allowlist",
    ),
    (
        "database",
        "network",
        "high",
        "Server exposes both database access and network access - risk of data exfiltration (query database, exfiltrate over network)",
        "Separate database tools from network-connected tools, or apply strict schema scoping",
    ),
    (
        "database",
        "execution",
        "high",
        "Server exposes both database access and shell execution - risk of total database compromise",
        "Gate shell execution behind human approval or isolate database credentials",
    ),
]


def analyze(server: MCPServer) -> List[SecurityFinding]:
    findings = []
    server_capabilities = set()
    for tool in server.tools:
        server_capabilities.update(tool.capabilities)

    for cap_a, cap_b, severity, message, fix in DANGEROUS_PAIRS:
        if cap_a in server_capabilities and cap_b in server_capabilities:
            findings.append(
                SecurityFinding(
                    severity=severity,
                    category="combined_risk",
                    tool_name=None,
                    server_name=server.name,
                    message=message,
                    fix=fix,
                    source_file=server.source_file,
                    source_line=1,
                )
            )
    return findings
