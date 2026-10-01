from pathlib import Path

from agentshield.discovery.manifest_parser import parse_manifest
from agentshield.discovery.sdk_detector import detect_python_server
from agentshield.discovery.server_finder import find_servers

FIXTURES = Path(__file__).parent / "fixtures"


def test_detect_python_server_finds_fastmcp_instance():
    source = (FIXTURES / "clean_server" / "server.py").read_text()
    server = detect_python_server(str(FIXTURES / "clean_server" / "server.py"), source)
    assert server is not None
    assert server.name == "local-fs-clean"
    assert server.sdk_type == "python-mcp"
    assert server.transport == "stdio"


def test_detect_python_server_returns_none_without_mcp_import():
    server = detect_python_server("plain.py", "def hello():\n    return 'hi'\n")
    assert server is None


def test_parse_mcp_servers_client_config():
    path = FIXTURES / "client_configs" / "claude_desktop_config.json"
    servers = parse_manifest(str(path))
    names = {s.name for s in servers}
    assert names == {"filesystem", "remote-tools"}
    remote = next(s for s in servers if s.name == "remote-tools")
    assert remote.transport == "sse"
    assert remote.auth_config is None


def test_find_servers_on_clean_fixture():
    servers = find_servers(str(FIXTURES / "clean_server"))
    assert len(servers) == 1
    assert servers[0].name == "local-fs-clean"


def test_find_servers_on_risky_fixture():
    servers = find_servers(str(FIXTURES / "risky_server"))
    assert len(servers) == 1
    assert servers[0].name == "dev-tools"
    assert len(servers[0].tools) == 4


def test_detect_python_server_finds_standalone_fastmcp_package():
    # regression test: the standalone `fastmcp` package (`from fastmcp
    # import FastMCP`) is a different import path from the official SDK's
    # `mcp.server.fastmcp` and was previously missed entirely.
    source = 'from fastmcp import FastMCP\n\nmcp = FastMCP("my-server")\n\n@mcp.tool()\ndef run(x: str) -> str:\n    return x\n'
    server = detect_python_server("server.py", source)
    assert server is not None
    assert server.name == "my-server"
    assert len(server.tools) == 1


def test_parse_manifest_survives_non_string_name(tmp_path):
    # regression test: a manifest with "name" as an object instead of a
    # string used to crash the whole scan with "unhashable type: dict"
    # once that value reached a dict key during deduplication.
    manifest = tmp_path / "mcp.json"
    manifest.write_text('{"name": {"nested": "object"}, "tools": [{"name": "t"}]}')
    servers = parse_manifest(str(manifest))
    assert len(servers) == 1
    assert isinstance(servers[0].name, str)


def test_parse_manifest_survives_pathological_json(tmp_path):
    top_level_list = tmp_path / "mcp.json"
    top_level_list.write_text('["not", "an", "object"]')
    assert parse_manifest(str(top_level_list)) == []

    bad_tools = tmp_path / "mcp2.json"
    bad_tools.write_text('{"tools": "not a list", "name": null}')
    servers = parse_manifest(str(bad_tools))
    assert len(servers) == 1
    assert servers[0].tools == []


def test_find_servers_skips_malformed_file_without_crashing(tmp_path):
    (tmp_path / "mcp.json").write_text('{"name": {"nested": "bad"}, "tools": []}')
    skipped = []
    servers = find_servers(str(tmp_path), skipped=skipped)
    # should not raise, and should still return a valid (coerced) server
    assert len(servers) == 1
    assert isinstance(servers[0].name, str)


def test_nested_transport_object_parsing(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text('{"name": "nested-server", "transport": {"type": "sse", "endpoint": "http://0.0.0.0:3000/sse", "auth": null, "tls": false}, "tools": []}')
    servers = parse_manifest(str(manifest))
    assert len(servers) == 1
    server = servers[0]
    assert server.transport == "sse"
    assert server.host == "0.0.0.0"
    assert server.tls is False
    assert server.auth_config is None


def test_stdio_tls_is_none():
    source = 'from fastmcp import FastMCP\nmcp = FastMCP("my-server")\nmcp.run(transport="stdio")'
    server = detect_python_server("server.py", source)
    assert server is not None
    assert server.transport == "stdio"
    assert server.tls is None

