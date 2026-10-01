from typing import Iterable

from ...models.tool import MCPTool


def mentions_any(tool: MCPTool, keywords: Iterable[str]) -> bool:
    """Best-effort check for whether a tool's description or schema property
    names/values reference a mitigation (e.g. 'sandbox', 'allowlist',
    'approval'). This is a static, description-level signal — it doesn't
    prove the mitigation is actually enforced in code, only that the tool
    author documented one. Absence of a mention is treated as absence of
    the mitigation."""
    haystack_parts = [tool.description or ""]

    props = tool.input_schema.get("properties", {}) if isinstance(tool.input_schema, dict) else {}
    if isinstance(props, dict):
        haystack_parts.extend(str(k) for k in props.keys())
        for v in props.values():
            if isinstance(v, dict):
                haystack_parts.append(str(v.get("description", "")))

    haystack = " ".join(haystack_parts).lower()
    return any(keyword.lower() in haystack for keyword in keywords)
