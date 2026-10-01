from typing import List

from ..models.server import MCPServer


def build_inventory(servers: List[MCPServer]) -> List[MCPServer]:
    """Deduplicate servers and sort deterministically so scan output is stable.

    Two-level deduplication (P1 fix):
    1. Exact key (name, source_file) — merges tools when the same server was
       discovered via both manifest and SDK detection in the same file.
    2. Name-only deduplication across different source files — when a server
       name appears in both a manifest entry and a code entry, the code entry
       is preferred (real line numbers) and the manifest entry is discarded,
       unless the code entry has 'unknown' transport (in which case the
       manifest's transport value is used as a fallback).
    """
    # Pass 1: exact (name, source_file) deduplication
    exact: dict = {}
    for server in servers:
        key = (server.name, server.source_file)
        if key not in exact:
            exact[key] = server
        else:
            # merge tools if the same server was discovered twice
            existing_tool_names = {t.name for t in exact[key].tools}
            for tool in server.tools:
                if tool.name not in existing_tool_names:
                    exact[key].tools.append(tool)

    # Pass 2: name-only cross-source deduplication
    by_name: dict = {}
    for server in exact.values():
        name = server.name
        if name not in by_name:
            by_name[name] = server
            continue

        existing = by_name[name]
        existing_is_code = existing.sdk_type != "manifest"
        new_is_code = server.sdk_type != "manifest"

        if new_is_code and not existing_is_code:
            # Prefer the code entry; adopt manifest transport if code has unknown
            if server.transport == "unknown" and existing.transport != "unknown":
                server.transport = existing.transport
            by_name[name] = server
        elif existing_is_code and not new_is_code:
            # Keep existing code entry; fill in transport from manifest if needed
            if existing.transport == "unknown" and server.transport != "unknown":
                existing.transport = server.transport
        else:
            # Both same type — merge tools into existing, keep existing
            existing_tool_names = {t.name for t in existing.tools}
            for tool in server.tools:
                if tool.name not in existing_tool_names:
                    existing.tools.append(tool)

    ordered = sorted(by_name.values(), key=lambda s: (s.source_file, s.name))
    for server in ordered:
        server.tools.sort(key=lambda t: t.name)
    return ordered
