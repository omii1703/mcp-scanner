from typing import List
from rich.console import Console
from rich.table import Table

from ..models.finding import SecurityFinding
from ..models.server import MCPServer
from .formatter import score_style, severity_label, severity_style


def render_table_report(
    servers: List[MCPServer],
    findings: List[SecurityFinding],
    overall_score: int,
    console: Console = None,
) -> None:
    console = console or Console()

    tool_count = sum(len(s.tools) for s in servers)
    console.print(
        f"\n[bold]AgentShield MCP Scan[/bold] - {len(servers)} server"
        f"{'s' if len(servers) != 1 else ''}, {tool_count} tool"
        f"{'s' if tool_count != 1 else ''} scanned\n"
    )

    if not findings:
        console.print("[bold green]No findings.[/bold green] All discovered tools passed static checks.\n")
    else:
        table = Table(title="Security Findings Summary", title_style="bold magenta")
        table.add_column("Severity", justify="left")
        table.add_column("Tool / Target", justify="left")
        table.add_column("Server", justify="left")
        table.add_column("Category", justify="left")
        table.add_column("OWASP Mapping", justify="left")
        table.add_column("Location", justify="left")

        for f in findings:
            label = f.tool_name if f.tool_name else "(server-level)"
            style = severity_style(f.severity)
            sev = severity_label(f.severity)
            
            # Short location representation
            loc = f"{Path(f.source_file).name}:{f.source_line}" if f.source_file else "unknown"
            
            table.add_row(
                f"[{style}]{sev}[/{style}]",
                label,
                f.server_name,
                f.category,
                f.owasp_id or "N/A",
                loc,
            )
            
        console.print(table)
        console.print()

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
from pathlib import Path
