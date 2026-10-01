import re
from typing import List, Tuple

from ...models.finding import SecurityFinding
from ...models.server import MCPServer
from ...models.tool import MCPTool
from ...patterns.registry import DB_LIBRARY_PATTERNS
from ._helpers import mentions_any

SCOPE_HINTS = ("read_only", "scoped", "restricted", "row_level", "allowlist")

_WRITE_RE = re.compile(r"\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE)\b", re.IGNORECASE)
_SELECT_RE = re.compile(r"\bSELECT\b", re.IGNORECASE)
_LIMIT_RE = re.compile(r"\bLIMIT\b", re.IGNORECASE)
_COMMIT_ROLLBACK = re.compile(r"\b(?:commit|rollback)\s*\(", re.IGNORECASE)

# Dynamic string formatting in execute call: e.g. execute(f"..."), execute("...".format(...)), execute("..." % ...)
_DYNAMIC_SQL_EXECUTE = re.compile(
    r"""\b(?:cursor|conn|engine|session)?\.execute\s*\(\s*(?:f["']|["'].*?%\s*|["'].*?\.format\()""",
    re.IGNORECASE,
)

# Raw parameter passed directly as single arg to execute: e.g. execute(sql), execute(query)
_RAW_EXECUTE_ARG = re.compile(
    r"""\b(?:cursor|conn|engine|session)?\.execute\s*\(\s*(?P<var>[a-zA-Z_]\w*)\s*\)""",
    re.IGNORECASE,
)


def _analyze_db_tool(tool: MCPTool) -> Tuple[str, str, str]:
    body = tool.source_body or ""
    if not body:
        return (
            "medium",
            "Database access with no scoping (read-only / row-level restriction) detected",
            "Scope to read-only queries or a restricted schema/table allowlist",
        )

    has_write = bool(_WRITE_RE.search(body))
    has_dynamic_exec = bool(_DYNAMIC_SQL_EXECUTE.search(body))
    has_commit_rollback = bool(_COMMIT_ROLLBACK.search(body))

    # 1. Check for RAW unparameterized SQL (CRITICAL - P0 Fix 3)
    raw_match = _RAW_EXECUTE_ARG.search(body)
    is_raw_sql = False
    if raw_match:
        var_name = raw_match.group("var")
        props = tool.input_schema.get("properties", {}) if isinstance(tool.input_schema, dict) else {}
        param_names = set(props.keys()) if isinstance(props, dict) else set()
        if var_name in param_names or var_name.lower() in ("sql", "query", "stmt", "statement", "sql_query", "raw_sql"):
            is_raw_sql = True

    if is_raw_sql:
        msg = "tool accepts raw SQL and executes it directly — equivalent to arbitrary code execution"
        if has_commit_rollback:
            msg += " (write capability confirmed)"
        return (
            "critical",
            msg,
            "use parameterized queries or restrict to a read-only connection with a query allowlist.",
        )

    # 2. Non-raw SQL severity classification (P1 Fix 7)
    msg = "Database access with no scoping (read-only / row-level restriction) detected"
    if has_commit_rollback:
        msg += " (write capability confirmed)"
    fix = "Scope to read-only queries or a restricted schema/table allowlist"

    # Check for ORM / NoSQL write or dynamic patterns
    nosql_write = any(h in body for h in [".insert_one(", ".update_one(", ".delete_one(", ".objects.create("])
    if has_write or has_dynamic_exec or has_commit_rollback or nosql_write:
        return "high", msg, fix

    has_select = bool(_SELECT_RE.search(body)) or any(h in body for h in [".query(", ".filter(", ".find(", ".objects.filter("])
    has_limit = bool(_LIMIT_RE.search(body)) or "limit(" in body or "[:" in body

    if has_select:
        if has_limit:
            return "low", msg, fix
        return "medium", msg, fix

    return "medium", msg, fix


def analyze(tool: MCPTool, server: MCPServer) -> List[SecurityFinding]:
    findings = []
    if "database" in tool.capabilities and not mentions_any(tool, SCOPE_HINTS):
        severity, message, fix = _analyze_db_tool(tool)
        findings.append(
            SecurityFinding(
                severity=severity,
                category="database",
                tool_name=tool.name,
                server_name=server.name,
                message=message,
                fix=fix,
                source_file=tool.source_file,
                source_line=tool.source_line,
            )
        )
    return findings
