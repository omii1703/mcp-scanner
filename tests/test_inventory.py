from pathlib import Path

from agentshield.discovery.server_finder import find_servers

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_server_tool_extraction():
    servers = find_servers(str(FIXTURES / "clean_server"))
    tool_names = {t.name for s in servers for t in s.tools}
    assert tool_names == {"read_file", "list_files"}


def test_clean_server_tools_have_filesystem_capability_only():
    servers = find_servers(str(FIXTURES / "clean_server"))
    for server in servers:
        for tool in server.tools:
            assert tool.capabilities == ["filesystem"]


def test_risky_server_capabilities_cover_all_categories():
    servers = find_servers(str(FIXTURES / "risky_server"))
    all_caps = set()
    for server in servers:
        for tool in server.tools:
            all_caps.update(tool.capabilities)
    assert all_caps == {"filesystem", "execution", "network", "database"}


def test_tool_schema_extracted_from_type_hints():
    servers = find_servers(str(FIXTURES / "risky_server"))
    write_file = next(t for s in servers for t in s.tools if t.name == "write_file")
    props = write_file.input_schema["properties"]
    assert props["path"]["type"] == "string"
    assert props["content"]["type"] == "string"
