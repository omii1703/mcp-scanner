import time
from pathlib import Path

from agentshield.analysis.analyzer import analyze_servers
from agentshield.discovery.server_finder import find_servers

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_server_scores_100_with_zero_findings():
    fixture_path = FIXTURES / "clean_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    assert findings == []
    assert score == 100


def test_risky_server_scores_below_70_with_five_plus_categories():
    fixture_path = FIXTURES / "risky_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    assert score < 70
    categories = {f.category for f in findings}
    assert len(categories) >= 5, f"only got categories: {categories}"


def test_risky_server_hits_expected_categories():
    fixture_path = FIXTURES / "risky_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    categories = {f.category for f in findings}
    assert {"filesystem", "execution", "network", "database", "injection", "combined_risk", "secrets", "transport"} <= categories


def test_risky_server_project_wide_secrets():
    """P0 Fix 1: Secret scan catches secrets in server.py AND helpers.py (5 total findings)."""
    fixture_path = FIXTURES / "risky_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    secret_findings = [f for f in findings if f.category == "secrets"]
    assert len(secret_findings) >= 5
    assert all(f.severity == "critical" for f in secret_findings)
    scanned_files = {Path(f.source_file).name for f in secret_findings}
    assert "server.py" in scanned_files
    assert "helpers.py" in scanned_files


def test_scan_runtime_under_two_seconds_on_fixtures():
    start = time.monotonic()
    for fixture in ("clean_server", "risky_server"):
        fixture_path = FIXTURES / fixture
        servers = find_servers(str(fixture_path))
        analyze_servers(servers, root_path=str(fixture_path))
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"scan took {elapsed:.2f}s"
