"""Extract MCP tool definitions (name, description, schema, capabilities)
from source code.

Python: AST-based — finds functions decorated with something like
`@mcp.tool()`, `@server.tool()`, `@app.tool(name=..., description=...)`.

Node/TypeScript: regex-based fallback — finds `server.tool("name", ...)`
/ `server.registerTool(...)` style calls. Less precise than the Python AST
path by design; the spec calls for "regex fallback" here, not a full JS
parser, to keep the dependency footprint at zero.
"""
import ast
from pathlib import Path
import re
from typing import List, Optional

from ..models.tool import MCPTool
from .call_graph import trace_transitive_bodies
from .schema_analyzer import detect_unclassified_calls, infer_capabilities

_PY_TYPE_MAP = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "List": "array",
    "dict": "object",
    "Dict": "object",
}


def _annotation_to_type(annotation: Optional[ast.expr]) -> str:
    if annotation is None:
        return "string"
    try:
        name = ast.unparse(annotation)
    except Exception:
        return "string"
    base = name.split("[")[0].strip()
    return _PY_TYPE_MAP.get(base, "string")


def _decorator_is_tool(dec: ast.expr) -> bool:
    """True if this decorator looks like <something>.tool(...), @tool(...),
    <something>.add_tool, or <something>.register_tool."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr in ("tool", "add_tool", "register_tool", "mcp_tool")
    if isinstance(target, ast.Name):
        return target.id in ("tool", "add_tool", "register_tool", "mcp_tool")
    return False


def _decorator_kwargs(dec: ast.expr) -> dict:
    if not isinstance(dec, ast.Call):
        return {}
    kwargs = {}
    for kw in dec.keywords:
        if kw.arg is None:
            continue
        try:
            kwargs[kw.arg] = ast.literal_eval(kw.value)
        except Exception:
            pass
    return kwargs


def _build_schema(func: ast.FunctionDef) -> dict:
    properties = {}
    required = []
    args = func.args.args
    for arg in args:
        if arg.arg in ("self", "cls"):
            continue
        properties[arg.arg] = {"type": _annotation_to_type(arg.annotation)}
        required.append(arg.arg)
    return {"type": "object", "properties": properties, "required": required}


def extract_python_tools(source: str, file_path: str, server_name: str) -> List[MCPTool]:
    tools: List[MCPTool] = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return tools

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tool_decorator = next((d for d in node.decorator_list if _decorator_is_tool(d)), None)
        if tool_decorator is None:
            continue

        kwargs = _decorator_kwargs(tool_decorator)
        name = kwargs.get("name", node.name)
        description = kwargs.get("description") or ast.get_docstring(node) or ""

        schema = _build_schema(node)

        try:
            source_body = ast.get_source_segment(source, node) or ""
        except Exception:
            source_body = ""

        # Follow locally-imported function calls up to 3 hops
        transitive_bodies, had_unresolved = trace_transitive_bodies(
            func_node=node,
            file_tree=tree,
            source_file=file_path,
        )
        combined_body = source_body + "\n" + "\n".join(transitive_bodies)

        capabilities = infer_capabilities(schema, description, combined_body)

        is_unknown = False
        unknown_reason = ""
        if len(capabilities) == 0:
            unclassified = detect_unclassified_calls(combined_body or source_body)
            if unclassified:
                is_unknown = True
                src_filename = Path(file_path).name
                unknown_reason = (
                    f"Calls {unclassified} in {src_filename}, which the scanner could not classify "
                    f"(no recognized network/DB/execution pattern matched). This does NOT mean the tool "
                    f"is safe — it means static analysis couldn't determine its behavior."
                )

        tools.append(
            MCPTool(
                name=name,
                description=description.strip(),
                input_schema=schema,
                server_name=server_name,
                source_file=file_path,
                source_line=node.lineno,
                capabilities=capabilities,
                source_body=source_body,
                unresolved_imports=had_unresolved,
                is_unknown=is_unknown,
                unknown_reason=unknown_reason,
            )
        )

    return tools


# --- Node / TypeScript regex fallback -------------------------------------

_NODE_TOOL_CALL = re.compile(
    r"""\.(?:tool|registerTool)\s*\(\s*["'](?P<name>[^"']+)["']\s*,\s*(?P<rest>.*?)\)\s*(?:;|,\s*(?:async\s*)?\()""",
    re.DOTALL,
)
_NODE_DESCRIPTION = re.compile(r"""description\s*:\s*["'`](?P<desc>[^"'`]*)["'`]""")


def extract_node_tools(source: str, file_path: str, server_name: str) -> List[MCPTool]:
    tools: List[MCPTool] = []
    for match in _NODE_TOOL_CALL.finditer(source):
        name = match.group("name")
        rest = match.group("rest") or ""
        desc_match = _NODE_DESCRIPTION.search(rest)
        description = desc_match.group("desc") if desc_match else ""

        schema = {"type": "object", "properties": {}, "required": []}
        line_no = source[: match.start()].count("\n") + 1

        window = source[max(0, match.start() - 200) : match.end() + 400]
        capabilities = infer_capabilities(schema, description, window)

        is_unknown = False
        unknown_reason = ""
        if len(capabilities) == 0:
            unclassified = detect_unclassified_calls(window)
            if unclassified:
                is_unknown = True
                src_filename = Path(file_path).name
                unknown_reason = (
                    f"Calls {unclassified} in {src_filename}, which the scanner could not classify "
                    f"(no recognized network/DB/execution pattern matched). This does NOT mean the tool "
                    f"is safe — it means static analysis couldn't determine its behavior."
                )

        tools.append(
            MCPTool(
                name=name,
                description=description.strip(),
                input_schema=schema,
                server_name=server_name,
                source_file=file_path,
                source_line=line_no,
                capabilities=capabilities,
                source_body=window,
                is_unknown=is_unknown,
                unknown_reason=unknown_reason,
            )
        )
    return tools
