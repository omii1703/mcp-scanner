"""Parse MCP manifest / config files (mcp.json, mcp.config.json, the "mcp"
field in package.json, and mcpServers-style client configs like
claude_desktop_config.json) into MCPServer objects.

These files don't contain source code to AST-walk, so tool capability
inference here relies purely on the schema + description text (no source
body available).
"""
import json
from pathlib import Path
from typing import List

from ..inventory.schema_analyzer import infer_capabilities
from ..models.server import MCPServer
from ..models.tool import MCPTool

MANIFEST_FILENAMES = {"mcp.json", "mcp.config.json"}
CLIENT_CONFIG_HINTS = ("claude_desktop_config.json", "mcp_config.json")


def _parse_direct_manifest(data: dict, file_path: str) -> List[MCPServer]:
    """Format: {"name": "...", "transport": "..." or {"type": "sse", ...}, "tools": [...]}"""
    name = data.get("name", Path(file_path).stem)
    name = str(name) if not isinstance(name, str) else name

    raw_transport = data.get("transport", "unknown")
    transport = "unknown"
    host = None
    port = None
    tls = None  # None = N/A (stdio/unknown); True/False = explicit for network transports
    auth_config = data.get("auth") or data.get("authentication")

    if isinstance(raw_transport, dict):
        transport = str(raw_transport.get("type", "unknown")).lower()
        endpoint = str(raw_transport.get("endpoint") or raw_transport.get("url") or "")
        if "0.0.0.0" in endpoint:
            host = "0.0.0.0"
        elif "127.0.0.1" in endpoint or "localhost" in endpoint:
            host = "127.0.0.1"

        if raw_transport.get("auth") is not None:
            auth_config = raw_transport.get("auth")

        # Only set tls for network transports; stdio/unknown → tls stays None
        if transport not in ("stdio", "unknown"):
            if "tls" in raw_transport:
                tls = bool(raw_transport.get("tls"))
            elif endpoint.startswith("https://"):
                tls = True
            else:
                tls = False
    elif isinstance(raw_transport, str):
        transport = raw_transport.lower()
    else:
        import warnings
        warnings.warn(f"Unrecognized transport format in manifest: {raw_transport}")

    server = MCPServer(
        name=name,
        source_file=file_path,
        sdk_type="manifest",
        transport=transport,
        auth_config=auth_config if auth_config else None,
        host=host,
        port=port,
        tls=tls,
    )

    for i, tool_def in enumerate(data.get("tools", [])):
        if not isinstance(tool_def, dict):
            continue
        tool_name = tool_def.get("name", f"tool_{i}")
        tool_name = str(tool_name) if not isinstance(tool_name, str) else tool_name
        description = tool_def.get("description", "")
        description = str(description) if not isinstance(description, str) else description
        schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
        if not isinstance(schema, dict):
            schema = {}
        capabilities = infer_capabilities(schema, description)
        server.tools.append(
            MCPTool(
                name=tool_name,
                description=description,
                input_schema=schema,
                server_name=name,
                source_file=file_path,
                source_line=1,
                capabilities=capabilities,
            )
        )
    return [server]


def _parse_mcp_servers_config(data: dict, file_path: str) -> List[MCPServer]:
    """Format: {"mcpServers": {"server-name": {"command": ..., "args": ...,
    "env": {...}, "url": ..., "headers": {...}}}}"""
    servers = []
    for name, cfg in data.get("mcpServers", {}).items():
        if not isinstance(cfg, dict):
            continue
        transport = "stdio" if "command" in cfg else ("sse" if "url" in cfg else "unknown")
        auth_config = None
        headers = cfg.get("headers")
        if headers or cfg.get("env"):
            auth_config = {"detected": True}

        server = MCPServer(
            name=name,
            source_file=file_path,
            sdk_type="manifest",
            transport=transport,
            auth_config=auth_config,
        )
        servers.append(server)
    return servers


def _parse_package_json(data: dict, file_path: str) -> List[MCPServer]:
    mcp_field = data.get("mcp")
    if not isinstance(mcp_field, dict):
        return []
    return _parse_direct_manifest(mcp_field, file_path)


def parse_manifest(file_path: str) -> List[MCPServer]:
    path = Path(file_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return []

    if not isinstance(data, dict):
        return []

    if path.name == "package.json":
        return _parse_package_json(data, file_path)

    if "mcpServers" in data:
        return _parse_mcp_servers_config(data, file_path)

    if "name" in data or "tools" in data:
        return _parse_direct_manifest(data, file_path)

    return []


def is_manifest_file(path: Path) -> bool:
    if path.name in MANIFEST_FILENAMES:
        return True
    if path.name == "package.json":
        return True
    if path.name in CLIENT_CONFIG_HINTS:
        return True
    return False
