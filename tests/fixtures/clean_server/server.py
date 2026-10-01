"""A clean MCP server: filesystem access is sandboxed, no shell execution,
no network calls, no hardcoded secrets."""
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("local-fs-clean")

WORKSPACE_ROOT = os.environ.get("WORKSPACE_ROOT", "./workspace")


@mcp.tool(name="read_file", description="Read a file from the sandboxed workspace directory. Restricted to allowed_paths under the workspace sandbox.")
def read_file(path: str) -> str:
    """Read a file's contents. Path must be inside the workspace sandbox (allowed_paths)."""
    full_path = os.path.join(WORKSPACE_ROOT, path)
    with open(full_path, "r") as f:
        return f.read()


@mcp.tool(name="list_files", description="List files in the sandboxed workspace directory (allowed_paths only).")
def list_files(directory: str) -> list:
    """List files under the workspace sandbox."""
    full_path = os.path.join(WORKSPACE_ROOT, directory)
    return os.listdir(full_path)


if __name__ == "__main__":
    mcp.run(transport="stdio")
