import json

from rich.console import Console

from agentshield.models.finding import SecurityFinding
from agentshield.models.server import MCPServer
from agentshield.reporting.json_out import build_json_report
from agentshield.reporting.terminal import render_terminal_report


def make_finding(severity="high"):
    return SecurityFinding(
        severity=severity,
        category="filesystem",
        tool_name="write_file",
        server_name="dev-tools",
        message="No path restriction",
        fix="Add allowed_paths",
        source_file="server.py",
        source_line=10,
    )


def test_terminal_report_contains_score_and_findings(capsys):
    server = MCPServer(name="dev-tools", source_file="server.py", sdk_type="python-mcp")
    findings = [make_finding()]
    console = Console(file=None, force_terminal=False, width=100)
    import io
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=100)
    render_terminal_report([server], findings, 85, console=console)
    output = buf.getvalue()
    assert "AgentShield MCP Scan" in output
    assert "write_file" in output
    assert "Overall MCP Security Score: 85/100" in output


def test_terminal_report_no_findings(capsys):
    import io
    server = MCPServer(name="clean", source_file="server.py", sdk_type="python-mcp")
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=100)
    render_terminal_report([server], [], 100, console=console)
    output = buf.getvalue()
    assert "No findings" in output
    assert "100/100" in output


def test_json_report_structure():
    server = MCPServer(name="dev-tools", source_file="server.py", sdk_type="python-mcp")
    findings = [make_finding()]
    report = build_json_report([server], findings, 85)
    assert report["overall_score"] == 85
    assert report["servers_scanned"] == 1
    assert report["finding_counts"]["high"] == 1
    assert json.dumps(report)  # must be JSON-serializable


def test_table_report_contains_score_and_findings():
    from agentshield.reporting.table_out import render_table_report
    import io
    server = MCPServer(name="dev-tools", source_file="server.py", sdk_type="python-mcp")
    findings = [make_finding()]
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120)
    render_table_report([server], findings, 85, console=console)
    output = buf.getvalue()
    assert "Security Findings Summary" in output
    assert "write_file" in output
    assert "filesystem" in output
    assert "LLM06:" in output  # OWASP ID check


def test_by_severity_report_contains_score_and_findings():
    from agentshield.reporting.by_severity_out import render_by_severity_report
    import io
    server = MCPServer(name="dev-tools", source_file="server.py", sdk_type="python-mcp")
    findings = [make_finding("critical")]
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=100)
    render_by_severity_report([server], findings, 50, console=console)
    output = buf.getvalue()
    assert "=== CRITICAL FINDINGS (1) ===" in output
    assert "Category: filesystem" in output

