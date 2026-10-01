from pathlib import Path
from typing import List

from .manifest_parser import CLIENT_CONFIG_HINTS


def find_client_configs(root: Path) -> List[Path]:
    """Locate MCP client config files under root (best-effort — these are
    informational, not a primary scan target in v1)."""
    found = []
    for hint in CLIENT_CONFIG_HINTS:
        found.extend(root.rglob(hint))
    return found
