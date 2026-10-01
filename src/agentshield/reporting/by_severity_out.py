from typing import List
from rich.console import Console

from ..models.finding import SecurityFinding
from ..models.server import MCPServer
from .formatter import score_style, severity_label, severity_style


def render_by_severity_report(
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
        f"{'s' if tool_count != 1 else ''} scanned (grouped by severity)\n"
    )

    if not findings:
        console.print("[bold green]No findings.[/bold green] All discovered tools passed static checks.\n")
    else:
        # Group by severity order
        by_sev = {"critical": [], "high": [], "medium": [], "low": []}
        for f in findings:
            if f.severity in by_sev:
                by_sev[f.severity].append(f)
            else:
                by_sev.setdefault(f.severity, []).append(f)

        for sev_name in ["critical", "high", "medium", "low"]:
            group = by_sev.get(sev_name, [])
            if not group:
                continue
            
            style = severity_style(sev_name)
            label = severity_label(sev_name)
            console.print(f"[{style}]=== {label} FINDINGS ({len(group)}) ===[/{style}]\n")
            
            for f in group:
                target = f.tool_name if f.tool_name else "server-level"
                console.print(f"  * [bold]{target}[/bold] (server: {f.server_name})")
                console.print(f"    -> Category: {f.category}")
                if f.owasp_id:
                    console.print(f"    -> OWASP: {f.owasp_id}")
                console.print(f"    -> Location: {f.source_file}:{f.source_line}")
                console.print(f"    -> Message: {f.message}")
                console.print(f"    -> Fix: {f.fix}\n")

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
