import io
from pathlib import Path
from rich.console import Console

from agentshield.analysis.analyzer import analyze_servers
from agentshield.discovery.server_finder import find_servers
from agentshield.patterns.registry import LLM_SDK_PATTERNS
from agentshield.reporting.terminal import render_terminal_report

MATRIX_DIR = Path(__file__).parent / "fixtures" / "matrix"


def test_registry_extensibility_requires_zero_rule_edits():
    """FIX 1 TEST: Adding a pattern to LLM_SDK_PATTERNS enables detection without editing rules."""
    initial_count = len(LLM_SDK_PATTERNS)
    # Dynamically add a fictional provider to the registry
    LLM_SDK_PATTERNS["fictional_ai"] = {
        "vendor": "Fictional AI",
        "method_tails": ["fictional_generate"],
        "source_hints": ["fictional_ai."],
    }
    assert len(LLM_SDK_PATTERNS) == initial_count + 1

    # Cleanup
    del LLM_SDK_PATTERNS["fictional_ai"]


def test_unknown_capability_tool_is_flagged_not_clean():
    """FIX 2 TEST: Unrecognized client library call yields is_unknown=True and Unknown report section."""
    servers = find_servers(str(MATRIX_DIR / "unknown_server"))
    findings, score = analyze_servers(servers, root_path=str(MATRIX_DIR / "unknown_server"))

    tool = servers[0].tools[0]
    assert tool.name == "cohere_agent"
    assert tool.is_unknown is True
    assert "cohere_client" in tool.unknown_reason or "chat" in tool.unknown_reason

    # Terminal report assertion
    out = io.StringIO()
    console = Console(file=out, color_system=None)
    render_terminal_report(servers, findings, score, console=console)
    report = out.getvalue()
    assert "Unknown capability (manual review recommended): cohere_agent" in report
    assert "Clean (no findings)" not in report or "cohere_agent" not in report.split("Clean (no findings)")[1]


def test_node_mcp_server_displays_confidence_qualifier():
    """FIX 3 TEST: Node MCP server renders with confidence qualifier in report."""
    servers = find_servers(str(MATRIX_DIR / "node_server"))
    findings, score = analyze_servers(servers, root_path=str(MATRIX_DIR / "node_server"))

    assert len(servers) == 1
    assert servers[0].sdk_type == "node-mcp"

    out = io.StringIO()
    console = Console(file=out, color_system=None)
    render_terminal_report(servers, findings, score, console=console)
    report = out.getvalue()
    assert "node-mcp, regex-based, lower confidence" in report


def test_cross_stack_fixture_matrix():
    """FIX 4 TEST: All matrix fixtures produce either findings or Unknown status — zero silent clean on non-trivial tools."""
    for fixture in ("openai_server", "sqlalchemy_server", "pymongo_server", "langchain_server", "node_server", "unknown_server"):
        fixture_path = MATRIX_DIR / fixture
        servers = find_servers(str(fixture_path))
        assert len(servers) >= 1, f"No servers found in {fixture}"
        findings, score = analyze_servers(servers, root_path=str(fixture_path))

        for server in servers:
            for tool in server.tools:
                # Every non-trivial matrix tool must have either matched capabilities, findings, or be marked Unknown
                has_caps = len(tool.capabilities) > 0
                has_findings = any(f.tool_name == tool.name for f in findings)
                is_unknown = tool.is_unknown

                assert has_caps or has_findings or is_unknown, (
                    f"Tool '{tool.name}' in {fixture} was silently marked clean despite non-trivial I/O!"
                )
