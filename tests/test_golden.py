from pathlib import Path
from agentshield.analysis.analyzer import analyze_servers
from agentshield.discovery.server_finder import find_servers

FIXTURES = Path(__file__).parent / "fixtures"

def test_clean_server_golden():
    fixture_path = FIXTURES / "clean_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    
    assert findings == []
    assert score == 100

def test_risky_server_golden():
    fixture_path = FIXTURES / "risky_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    
    # Assert exact tuples of (tool_name, category, severity)
    # This prevents any findings from silently disappearing in future changes.
    finding_tuples = {(f.tool_name, f.category, f.severity) for f in findings}
    
    expected_tuples = {
        # Tool findings
        ("write_file", "filesystem", "high"),
        ("run_command", "execution", "critical"),
        ("run_command", "injection", "critical"),
        ("fetch_url", "network", "high"),
        ("run_query", "database", "critical"), # accepts raw SQL query
        
        # Combined risk findings (deduplicated to highest severity: critical)
        (None, "combined_risk", "critical"),
        
        # Transport findings (deduplicated to highest severity: high)
        (None, "transport", "high"),
        
        # Secrets findings (including server.py and helpers.py)
        (None, "secrets", "critical"),
    }
    
    # Check that all expected rule findings are present
    for expected in expected_tuples:
        assert expected in finding_tuples, f"Missing expected finding: {expected}"

    # Also assert project-wide secrets has real file locations (not blank server_name)
    secret_findings = [f for f in findings if f.category == "secrets"]
    assert len(secret_findings) >= 5
    for sf in secret_findings:
        assert sf.server_name != ""
        assert sf.server_name.startswith("dev-tools") or sf.server_name.startswith("project-file:")

def test_openai_server_golden():
    fixture_path = FIXTURES / "matrix" / "openai_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    
    finding_tuples = {(f.tool_name, f.category, f.severity) for f in findings}
    
    # generate_sql tool uses openai library to generate SQL and executes it with sqlite3.
    assert ("generate_sql", "llm_code_execution", "critical") in finding_tuples
    assert ("generate_sql", "database", "critical") in finding_tuples # raw execution of sql param
    assert (None, "secrets", "critical") in finding_tuples

def test_sqlalchemy_server_golden():
    fixture_path = FIXTURES / "matrix" / "sqlalchemy_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    
    finding_tuples = {(f.tool_name, f.category, f.severity) for f in findings}
    assert ("get_user", "database", "medium") in finding_tuples

def test_pymongo_server_golden():
    fixture_path = FIXTURES / "matrix" / "pymongo_server"
    servers = find_servers(str(fixture_path))
    findings, score = analyze_servers(servers, root_path=str(fixture_path))
    
    finding_tuples = {(f.tool_name, f.category, f.severity) for f in findings}
    assert ("find_document", "database", "medium") in finding_tuples
