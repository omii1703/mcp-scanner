import os
from pathlib import Path
from typing import List, Tuple

from ..inventory.inventory_builder import build_inventory
from ..models.server import MCPServer
from .manifest_parser import is_manifest_file, parse_manifest
from .sdk_detector import detect_node_server, detect_python_server

EXCLUDED_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".mypy_cache", ".pytest_cache", "site-packages",
    ".tox", "target", ".next", "coverage",
}

PY_EXT = {".py"}
NODE_EXT = {".js", ".ts", ".mjs", ".cjs"}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def find_servers(root_path: str, skipped: List[Tuple[str, str]] = None) -> List[MCPServer]:
    """Walk root_path and discover MCP servers. A file that fails to parse
    (malformed manifest, unreadable source, unexpected structure) is
    recorded in `skipped` (if provided) and the scan continues — one bad
    file must never take down the whole scan, especially since scan targets
    are often untrusted/adversarial code by definition."""
    root = Path(root_path).resolve()
    servers: List[MCPServer] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            suffix = file_path.suffix.lower()

            try:
                if is_manifest_file(file_path):
                    servers.extend(parse_manifest(str(file_path)))
                    continue

                if suffix in PY_EXT:
                    source = _read_text(file_path)
                    if not source:
                        continue
                    server = detect_python_server(str(file_path), source)
                    if server:
                        servers.append(server)
                    continue

                if suffix in NODE_EXT:
                    source = _read_text(file_path)
                    if not source:
                        continue
                    server = detect_node_server(str(file_path), source)
                    if server:
                        servers.append(server)
            except Exception as exc:  # noqa: BLE001 - deliberate: never let one file kill the scan
                if skipped is not None:
                    skipped.append((str(file_path), f"{type(exc).__name__}: {exc}"))
                continue

    return build_inventory(servers)
