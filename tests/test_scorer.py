from agentshield.analysis.risk_scorer import apply_tool_risk_scores, compute_overall_score
from agentshield.models.finding import SecurityFinding
from agentshield.models.server import MCPServer
from agentshield.models.tool import MCPTool


def make_finding(severity, tool_name=None, server_name="s"):
    return SecurityFinding(
        severity=severity,
        category="filesystem",
        tool_name=tool_name,
        server_name=server_name,
        message="msg",
        fix="fix",
        source_file="test.py",
        source_line=1,
    )


def test_compute_overall_score_no_findings():
    # No servers, no findings — perfect score, no confidence penalty
    assert compute_overall_score([], []) == 100


def test_compute_overall_score_deductions():
    findings = [make_finding("critical"), make_finding("high"), make_finding("medium"), make_finding("low")]
    score = compute_overall_score([], findings)
    assert 50 <= score <= 60


def test_compute_overall_score_approaches_zero_but_never_negative():
    findings = [make_finding("critical") for _ in range(20)]
    score = compute_overall_score([], findings)
    assert 0 <= score < 5


def test_compute_overall_score_single_critical_stays_meaningful():
    # one critical finding shouldn't tank the score to near-zero
    score = compute_overall_score([], [make_finding("critical")])
    assert score == 72


def test_apply_tool_risk_scores_uses_worst_severity():
    tool = MCPTool(name="t", description="", input_schema={}, server_name="s", source_file="test.py", source_line=1)
    server = MCPServer(name="s", source_file="test.py", sdk_type="python-mcp", tools=[tool])
    findings = [make_finding("medium", tool_name="t"), make_finding("critical", tool_name="t")]
    apply_tool_risk_scores([server], findings)
    assert tool.risk_score == "critical"


def test_apply_tool_risk_scores_defaults_to_low():
    tool = MCPTool(name="t", description="", input_schema={}, server_name="s", source_file="test.py", source_line=1)
    server = MCPServer(name="s", source_file="test.py", sdk_type="python-mcp", tools=[tool])
    apply_tool_risk_scores([server], [])
    assert tool.risk_score == "low"
