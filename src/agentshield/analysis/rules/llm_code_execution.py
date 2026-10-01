"""Detect LLM-generated code flowing into dangerous execution sinks.

This is one of the highest-risk patterns in AI-powered MCP tools: when the
output of a generative model (e.g. Gemini, GPT-4, Claude) is passed directly
into database query execution, shell execution, or code evaluation without
validation/parameterisation.

Category: llm_code_execution
Severity: critical
"""
import re
from typing import List, Optional, Set, Tuple

from ...models.finding import SecurityFinding
from ...models.server import MCPServer
from ...models.tool import MCPTool
from ...patterns.registry import LLM_SDK_PATTERNS, get_all_llm_method_tails

# Build LLM assignment pattern dynamically from pattern registry (FIX 1)
_ACCESSOR_PATTERNS = [r"\.text\b", r"\.content\b", r"\.choices\b", r"\.candidates\b"]
for _sdk in LLM_SDK_PATTERNS.values():
    for tail in _sdk.get("method_tails", []):
        escaped = re.escape(tail).replace(r"\.", r"\.")
        _ACCESSOR_PATTERNS.append(rf"{escaped}\s*\(")

_ASSIGN_REGEX_STR = rf"""(?x)
^\s*                          # leading whitespace
(?P<var>\w+)                  # local variable name
\s*=\s*                       # assignment
.*?                           # right-hand side expression
(?:
    {" | ".join(_ACCESSOR_PATTERNS)}
)
"""

_LLM_ASSIGN_RE = re.compile(_ASSIGN_REGEX_STR, re.MULTILINE)

# Variable re-assignment tracker: e.g. sql = res.text; final_query = sql
_REASSIGN_RE = re.compile(
    r"""^\s*(?P<var>\w+)\s*=\s*.*?\b(?P<orig>\w+)\b""",
    re.MULTILINE,
)

# Execution sinks with human-friendly sink names
_SINK_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"""\bcursor\.execute\b"""), "cursor.execute"),
    (re.compile(r"""\bconn\.execute\b"""), "conn.execute"),
    (re.compile(r"""\b\.execute\b"""), "execute"),
    (re.compile(r"""\beval\s*\("""), "eval"),
    (re.compile(r"""\bexec\s*\("""), "exec"),
    (re.compile(r"""\bcompile\s*\("""), "compile"),
    (re.compile(r"""\bsubprocess\.(?:run|Popen|call|check_output)\b"""), "subprocess.run"),
    (re.compile(r"""\bos\.system\b"""), "os.system"),
    (re.compile(r"""\bos\.popen\b"""), "os.popen"),
    (re.compile(r"""\bopen\s*\("""), "open"),
]


def _check_body(source_body: str, tool_name: str, server_name: str, source_file: str, base_line: int) -> Optional[SecurityFinding]:
    lines = source_body.splitlines()
    llm_vars: Set[str] = set()

    # Dynamically query tails and hints from registry to build search substrings
    accessors = [".text", ".content", ".choices", ".candidates", ".message.content"]
    for tail in get_all_llm_method_tails():
        accessors.append(tail)

    for i, line in enumerate(lines):
        # Scan line for assignment: var = ...
        if "=" in line:
            parts = line.split("=", 1)
            lhs = parts[0].strip()
            rhs = parts[1]
            
            # Match identifier on LHS
            lhs_match = re.match(r"^\s*(?P<var>[a-zA-Z_]\w*)\s*$", lhs)
            if lhs_match:
                var_name = lhs_match.group("var")
                
                # Case 1: Right-hand side calls or references an LLM output accessor or method tail
                has_accessor = any(acc in rhs for acc in accessors)
                if has_accessor:
                    llm_vars.add(var_name)
                    
                # Case 2: Simple reassignment from an existing LLM variable
                else:
                    for orig in list(llm_vars):
                        if re.search(r"\b" + re.escape(orig) + r"\b", rhs):
                            llm_vars.add(var_name)

        if not llm_vars:
            continue

        # Scan line for any sink receiving one of our llm_vars
        for var in llm_vars:
            var_re = re.compile(r"""\b""" + re.escape(var) + r"""\b""")
            if not var_re.search(line):
                continue

            for sink_re, sink_name in _SINK_PATTERNS:
                if sink_re.search(line):
                    sink_line = base_line + i
                    return SecurityFinding(
                        severity="critical",
                        category="llm_code_execution",
                        tool_name=tool_name,
                        server_name=server_name,
                        message=f"LLM-generated output flows into {sink_name} without validation",
                        fix="add a validation layer — parameterized queries, an allowlist, or sandboxed execution.",
                        source_file=source_file,
                        source_line=sink_line,
                    )
    return None


def analyze(tool: MCPTool, server: MCPServer) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    if not tool.source_body:
        return findings
    finding = _check_body(
        source_body=tool.source_body,
        tool_name=tool.name,
        server_name=server.name,
        source_file=tool.source_file,
        base_line=tool.source_line,
    )
    if finding:
        findings.append(finding)
    return findings
