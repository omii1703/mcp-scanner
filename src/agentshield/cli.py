import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from . import __version__
from .analysis.analyzer import analyze_servers
from .discovery.server_finder import find_servers
from .reporting.json_out import render_json_report
from .reporting.terminal import render_terminal_report
from .reporting.table_out import render_table_report
from .reporting.by_severity_out import render_by_severity_report

app = typer.Typer(add_completion=False, help="AgentShield — MCP security scanner.")
console = Console()


def _version_callback(value: bool):
    if value:
        console.print(f"agentshield {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
):
    pass


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to the project to scan."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of the terminal report."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write output to a file instead of stdout."),
    format_opt: str = typer.Option("terminal", "--format", help="Output format: terminal, table, by-severity."),
):
    """Scan a project for MCP server security issues."""
    target = Path(path)
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] path does not exist: {path}")
        raise typer.Exit(code=2)

    try:
        skipped: list = []
        with console.status("[bold blue]Scanning for MCP servers...", spinner="dots"):
            servers = find_servers(str(target), skipped=skipped)
            findings, overall_score = analyze_servers(servers, root_path=str(target))
    except Exception as exc:  # noqa: BLE001 - CLI top-level guard
        console.print(f"[bold red]Error during scan:[/bold red] {exc}")
        raise typer.Exit(code=2)

    if skipped:
        console.print(f"[yellow]Warning:[/yellow] {len(skipped)} file(s) could not be parsed and were skipped:")
        for file_path, reason in skipped[:10]:
            console.print(f"  - {file_path}: {reason}")
        if len(skipped) > 10:
            console.print(f"  ... and {len(skipped) - 10} more")
        console.print()

    # Determine reporting function
    if json_output:
        report_text = render_json_report(servers, findings, overall_score)
        if output:
            Path(output).write_text(report_text, encoding="utf-8")
            console.print(f"JSON report written to {output}")
        else:
            print(report_text)
    else:
        # Route depending on --format
        fmt = format_opt.lower()
        if fmt == "table":
            render_fn = render_table_report
        elif fmt == "by-severity":
            render_fn = render_by_severity_report
        else:
            render_fn = render_terminal_report

        if output:
            file_console = Console(file=open(output, "w", encoding="utf-8"))
            render_fn(servers, findings, overall_score, console=file_console)
            console.print(f"Report written to {output}")
        else:
            render_fn(servers, findings, overall_score, console=console)

    raise typer.Exit(code=1 if findings else 0)


def cli_main():
    app()


if __name__ == "__main__":
    cli_main()
