from dataclasses import dataclass, field
from typing import List


@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: dict
    server_name: str
    source_file: str
    source_line: int
    capabilities: List[str] = field(default_factory=list)
    risk_score: str = "low"  # "low", "medium", "high", "critical"
    # Raw source text of the tool function body — used by taint-analysis rules
    # (e.g. llm_code_execution) so they don't need to re-read files themselves.
    source_body: str = ""
    # Set by the call-graph tracer when a local import could not be resolved.
    unresolved_imports: bool = False
    # Set when a tool has zero matched capabilities but calls unclassified external code (FIX 2)
    is_unknown: bool = False
    unknown_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "server_name": self.server_name,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "capabilities": self.capabilities,
            "risk_score": self.risk_score,
            "is_unknown": self.is_unknown,
            "unknown_reason": self.unknown_reason,
        }
