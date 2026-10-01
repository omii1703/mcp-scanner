"""Infer capability hints (filesystem, execution, network, database) from a
tool's JSONSchema properties, description text, and source code body using the
centralized pattern registry.

Also detects unclassified external calls (FIX 2) when a tool has zero matched
capabilities but calls into code the scanner cannot classify.
"""
import ast
import re
from typing import List, Optional, Tuple

from ..patterns.registry import (
    DB_LIBRARY_PATTERNS,
    EXECUTION_PATTERNS,
    FILESYSTEM_PATTERNS,
    LLM_SDK_PATTERNS,
    NETWORK_PATTERNS,
    STDLIB_CALL_HINTS,
    get_all_db_source_hints,
    get_all_execution_source_hints,
    get_all_filesystem_source_hints,
    get_all_network_source_hints,
)

FILESYSTEM_PROP_HINTS = {"path", "file", "filepath", "filename", "dir", "directory", "folder"}
EXECUTION_PROP_HINTS = {"command", "cmd", "shell", "script", "code", "args"}
NETWORK_PROP_HINTS = {"url", "uri", "endpoint", "host", "domain", "address"}
DATABASE_PROP_HINTS = {"sql", "table", "collection", "database", "db"}


def _schema_property_names(schema: dict) -> List[str]:
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return []
    return [str(k).lower() for k in props.keys()]


def infer_capabilities(schema: dict, description: str = "", source_body: str = "") -> List[str]:
    """Return a sorted list of capability tags detected for a tool based on the registry."""
    capabilities = set()
    prop_names = _schema_property_names(schema)
    text = (description or "").lower()
    body = source_body or ""

    fs_hints = get_all_filesystem_source_hints()
    exec_hints = get_all_execution_source_hints()
    net_hints = get_all_network_source_hints()
    db_hints = get_all_db_source_hints()

    if any(p in FILESYSTEM_PROP_HINTS for p in prop_names) or any(h in body for h in fs_hints):
        capabilities.add("filesystem")

    if any(p in EXECUTION_PROP_HINTS for p in prop_names) or any(h in body for h in exec_hints):
        capabilities.add("execution")

    url_patterns = NETWORK_PATTERNS.get("url_patterns", {}).get("patterns", [])
    if (
        any(p in NETWORK_PROP_HINTS for p in prop_names)
        or any(h in body for h in net_hints)
        or any(url in body for url in url_patterns)
        or any(url in text for url in url_patterns)
    ):
        capabilities.add("network")

    has_db_prop = any(p in DATABASE_PROP_HINTS for p in prop_names)
    has_db_source = any(h in body for h in db_hints)
    has_query_prop = "query" in prop_names

    if has_db_prop or has_db_source or (has_query_prop and has_db_source):
        capabilities.add("database")

    return sorted(capabilities)


def detect_unclassified_calls(source_body: str) -> Optional[str]:
    """FIX 2: Detect if a tool body makes external function or method calls
    that do not match any recognized registry patterns.

    Returns the call name string if unclassified external calls exist, or None
    if the body contains only standard operations or recognized patterns.
    """
    if not source_body or not source_body.strip():
        return None

    try:
        tree = ast.parse(source_body)
    except SyntaxError:
        # Regex fallback for non-Python or syntax-invalid snippets
        matches = re.findall(r"\b([a-zA-Z_]\w*)\s*\(", source_body)
        for name in matches:
            if name.lower() not in STDLIB_CALL_HINTS:
                return f"{name}()"
        return None

    unclassified_call = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = None
        func = node.func
        if isinstance(func, ast.Name):
            call_name = func.id
        elif isinstance(func, ast.Attribute):
            call_name = func.attr

        if not call_name:
            continue

        lowered_name = call_name.lower()
        if lowered_name in STDLIB_CALL_HINTS:
            continue

        # Check if the call expression itself matches any known registry hint
        call_expr = ast.unparse(func) if hasattr(ast, "unparse") else call_name
        is_recognized = False

        all_recognized_hints = (
            get_all_filesystem_source_hints()
            + get_all_execution_source_hints()
            + get_all_network_source_hints()
            + get_all_db_source_hints()
        )

        for hint in all_recognized_hints:
            clean_hint = hint.rstrip("(").rstrip(".")
            if clean_hint in call_expr or clean_hint == call_name:
                is_recognized = True
                break

        if not is_recognized:
            return f"{call_expr}()"

    return unclassified_call
