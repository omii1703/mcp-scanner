"""Detect MCP server implementations via SDK usage (Python `mcp` package,
Node `@modelcontextprotocol/sdk`), as opposed to manifest files which are
handled by manifest_parser.py.

P1 fix: detection is now instantiation-based (AST), not import-based.
    A file that merely does ``from fastmcp import FastMCP`` is NOT a server.
    We require an actual assignment: ``mcp = FastMCP("name")`` or similar.

P5 fix: transport is parsed from the AST of mcp.run() / server.run() calls,
    extracting transport type, host, port, and TLS flag instead of doing a
    keyword search.
"""
import ast
import re
from pathlib import Path
from typing import Optional, Tuple

from ..inventory.tool_extractor import extract_node_tools, extract_python_tools
from ..models.server import MCPServer

# ── Node helpers (unchanged — no AST parser available for JS/TS) ──────────
_NODE_IMPORT_RE = re.compile(r"""@modelcontextprotocol/sdk""")
_NODE_NAME_RE = re.compile(
    r"""new\s+(?:McpServer|Server)\s*\(\s*\{[^}]*?name\s*:\s*["'`](?P<name>[^"'`]+)["'`]""",
    re.DOTALL,
)
_NODE_AUTH_RE = re.compile(r"""\b(apiKey|authToken|Authorization|bearerToken)\b""")

# Node transport: still regex because we don't parse JS
_NODE_TRANSPORT_RE = re.compile(r"""\b(stdio|sse|http|streamablehttp)\b""", re.IGNORECASE)

# Auth hint regex (Python) — used as a cheap pre-scan
_PY_AUTH_RE = re.compile(
    r"""\b(api_key|auth_token|Authorization|bearer_token)\b""", re.IGNORECASE
)

# SDK class names that constitute "instantiation"
_SERVER_CLASS_NAMES = {"FastMCP", "Server", "McpServer"}


# ── P1: AST-based Python server detection ────────────────────────────────

def _find_server_instantiation(tree: ast.Module) -> Optional[str]:
    """Walk the AST looking for an assignment whose right-hand side is a Call
    to FastMCP(...), Server(...), or McpServer(...).

    Returns the server name string if found in the call's first positional
    argument or the ``name=`` keyword, or None if no instantiation exists.

    Examples that ARE detected::

        mcp = FastMCP("My Server")
        server = Server(name="foo")
        app: FastMCP = FastMCP("bar", version="1.0")

    Examples that are NOT detected (and must not be flagged)::

        from fastmcp import FastMCP          # pure import
        FastMCP  # bare name reference
    """
    for node in ast.walk(tree):
        # We want any assignment (Assign / AnnAssign / augmented) whose value
        # is a Call to one of the server class names.
        call_node: Optional[ast.Call] = None

        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                call_node = node.value
        elif isinstance(node, ast.AnnAssign):
            if node.value and isinstance(node.value, ast.Call):
                call_node = node.value

        if call_node is None:
            continue

        # Resolve the function being called
        func = call_node.func
        class_name: Optional[str] = None
        if isinstance(func, ast.Name):
            class_name = func.id
        elif isinstance(func, ast.Attribute):
            class_name = func.attr

        if class_name not in _SERVER_CLASS_NAMES:
            continue

        # Extract the server name from the call arguments
        # 1. First positional argument (string literal)
        if call_node.args:
            first = call_node.args[0]
            try:
                val = ast.literal_eval(first)
                if isinstance(val, str):
                    return val
            except Exception:
                pass

        # 2. name= keyword argument
        for kw in call_node.keywords:
            if kw.arg == "name":
                try:
                    val = ast.literal_eval(kw.value)
                    if isinstance(val, str):
                        return val
                except Exception:
                    pass

        # Found an instantiation but couldn't extract a literal name
        return None  # caller uses stem as fallback

    return None  # no instantiation found → not a server file


# ── P5: AST-based mcp.run() transport parsing ────────────────────────────

def _parse_run_call(tree: ast.Module) -> Tuple[str, Optional[str], Optional[int], Optional[bool]]:
    """Find a mcp.run() / server.run() / app.run() call in the AST and
    extract (transport, host, port, tls).

    Falls back to regex-based string scanning if not found in the AST.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        call = node.value
        # Match *.run(...)
        func = call.func
        if not (isinstance(func, ast.Attribute) and func.attr == "run"):
            continue

        transport: str = "unknown"
        host: Optional[str] = None
        port: Optional[int] = None
        tls: Optional[bool] = None

        # Positional arg 0 is sometimes the transport string
        if call.args:
            try:
                val = ast.literal_eval(call.args[0])
                if isinstance(val, str):
                    transport = val.lower()
            except Exception:
                pass

        for kw in call.keywords:
            try:
                val = ast.literal_eval(kw.value)
            except Exception:
                continue
            if kw.arg == "transport" and isinstance(val, str):
                transport = val.lower()
            elif kw.arg == "host" and isinstance(val, str):
                host = val
            elif kw.arg == "port" and isinstance(val, int):
                port = val
            elif kw.arg in ("ssl", "tls") and isinstance(val, bool):
                tls = val

        return transport, host, port, tls

    return "unknown", None, None, None


def _detect_transport_fallback(source: str) -> str:
    """Regex fallback when no AST run() call is found (e.g. transport set
    from an env variable or config dict)."""
    lowered = source.lower()
    if "sse" in lowered or "server-sent" in lowered:
        return "sse"
    if "streamablehttp" in lowered.replace("_", "").replace("-", "") or "streamable_http" in lowered:
        return "http"
    if "stdio" in lowered:
        return "stdio"
    return "unknown"


# ── Public API ────────────────────────────────────────────────────────────

def detect_python_server(file_path: str, source: str) -> Optional[MCPServer]:
    """Return an MCPServer if the file instantiates a known MCP server class,
    or None if it only imports the SDK without using it (P1 fix)."""
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return None

    # P1: Require actual instantiation, not just an import
    name_or_sentinel = _find_server_instantiation(tree)
    if name_or_sentinel is None:
        return None  # file imports fastmcp but never instantiates → skip

    name = name_or_sentinel if name_or_sentinel else Path(file_path).stem

    # P5: Parse mcp.run() kwargs for structured transport info
    transport, host, port, tls = _parse_run_call(tree)
    if transport == "unknown":
        transport = _detect_transport_fallback(source)

    # stdio is a local pipe — TLS is not a meaningful concept for it.
    if transport == "stdio":
        tls = None

    server = MCPServer(
        name=name,
        source_file=file_path,
        sdk_type="python-mcp",
        transport=transport,
        auth_config={"detected": True} if _PY_AUTH_RE.search(source) else None,
        host=host,
        port=port,
        tls=tls,
    )
    server.tools = extract_python_tools(source, file_path, name)
    return server


def detect_node_server(file_path: str, source: str) -> Optional[MCPServer]:
    if not _NODE_IMPORT_RE.search(source):
        return None

    name_match = _NODE_NAME_RE.search(source)
    name = name_match.group("name") if name_match else Path(file_path).stem

    # Node transport: regex only (no JS AST parser)
    transport_match = _NODE_TRANSPORT_RE.search(source)
    transport = transport_match.group(1).lower() if transport_match else "unknown"
    if transport == "streamablehttp":
        transport = "http"

    server = MCPServer(
        name=name,
        source_file=file_path,
        sdk_type="node-mcp",
        transport=transport,
        auth_config={"detected": True} if _NODE_AUTH_RE.search(source) else None,
    )
    server.tools = extract_node_tools(source, file_path, name)
    return server
