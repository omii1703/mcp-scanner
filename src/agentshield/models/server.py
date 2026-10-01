from dataclasses import dataclass, field
from typing import List, Optional

from .tool import MCPTool


@dataclass
class MCPServer:
    name: str
    source_file: str
    sdk_type: str  # "python-mcp", "node-mcp", "manifest"
    transport: str = "unknown"  # "stdio", "sse", "http", "unknown"
    auth_config: Optional[dict] = None
    tools: List[MCPTool] = field(default_factory=list)
    # Populated by AST-based mcp.run() argument parsing (P5)
    host: Optional[str] = None
    port: Optional[int] = None
    # None = not applicable (stdio is a local pipe; TLS is meaningless for it).
    # True/False = TLS enabled/disabled for network transports (SSE, HTTP).
    tls: Optional[bool] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source_file": self.source_file,
            "sdk_type": self.sdk_type,
            "transport": self.transport,
            "auth_config": self.auth_config,
            "host": self.host,
            "port": self.port,
            "tls": self.tls,
            "tools": [t.to_dict() for t in self.tools],
        }

