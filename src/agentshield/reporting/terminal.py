from typing import List

from rich.console import Console

from ..models.finding import SecurityFinding
from ..models.server import MCPServer
from .formatter import score_style, severity_label, severity_style


def render_terminal_report(
    servers: List[MCPServer],
    findings: List[SecurityFinding],
    overall_score: int,
    console: Console = None,
) -> None:
    console = console or Console()

    tool_count = sum(len(s.tools) for s in servers)
    header_parts = []
    for s in servers:
        if s.sdk_type == "node-mcp":
            header_parts.append(f"{s.name} [yellow](node-mcp, regex-based, lower confidence)[/yellow]")

    console.print(
        f"\n[bold]AgentShield MCP Scan[/bold] - {len(servers)} server"
        f"{'s' if len(servers) != 1 else ''}, {tool_count} tool"
        f"{'s' if tool_count != 1 else ''} discovered\n"
    )

    if header_parts:
        console.print("[dim]Server SDK Types / Confidence:[/dim]")
        for hp in header_parts:
            console.print(f"  - {hp}")
        console.print()

    all_tools = [tool for server in servers for tool in server.tools]
    flagged_tool_names = {finding.tool_name for finding in findings if finding.tool_name}

    unknown_tools = [tool for tool in all_tools if tool.is_unknown]
    clean_tool_names = [
        tool.name for tool in all_tools
        if tool.name not in flagged_tool_names and not tool.is_unknown
    ]

    if not findings:
        console.print("[bold green]No findings.[/bold green] All discovered tools passed static checks.\n")
    else:
        for finding in findings:
            label = finding.tool_name if finding.tool_name else "server-level"
            style = severity_style(finding.severity)
            sev = severity_label(finding.severity)
            console.print(f"[{style}]{sev:<8}[/{style}]  {label} (server: {finding.server_name})")
            console.print(f"  -> {finding.message}")
            if finding.owasp_id:
                console.print(f"  -> Maps to: OWASP {finding.owasp_id}")
            console.print(f"  -> Fix: {finding.fix}\n")

    if clean_tool_names:
        console.print(f"[dim]Clean (no findings): {', '.join(clean_tool_names)}[/dim]\n")

    if unknown_tools:
        for tool in unknown_tools:
            console.print(f"[bold yellow]Unknown capability (manual review recommended): {tool.name}[/bold yellow]")
            console.print(f"  -> {tool.unknown_reason}\n")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    console.print(
        f"[{score_style(overall_score)}]Overall MCP Security Score: {overall_score}/100[/{score_style(overall_score)}]"
    )
    console.print(
        f"Servers scanned: {len(servers)}   Tools scanned: {tool_count}   "
        f"Critical: {counts['critical']}   High: {counts['high']}   "
        f"Medium: {counts['medium']}   Low: {counts['low']}\n"
    )
