# Changelog

All notable changes to AgentShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-25

### Added
- **LLM-Generated Code Execution Rule (`llm_code_execution`)**: Critical-severity rule catching unparameterised LLM response text flowing into `cursor.execute()`, `eval()`, `exec()`, `compile()`, `os.system()`, `subprocess.run()`, or `.execute()`.
- **Transitive Capability Tracing**: AST-based call-graph tracer that follows local function calls into imported agent/helper modules (up to 2 hops) to discover transitive capabilities.
- **Confidence Penalty**: Score calculation now applies a confidence penalty (up to 25 points) when server transport is unknown, tool descriptions are missing, or imports are unresolvable.
- **Structured Transport & Manifest Parsing**: Support for dict-style `transport` objects in `mcp.json`, including `endpoint`, `auth`, `tls`, and `0.0.0.0` interface binding detection.

### Changed
- **Eliminated False Database Positive on Chat Parameters**: Bare `query` parameters without database source hints (imports/calls) are no longer wrongly tagged as `database` capabilities.
- **Instantiation-Based Python Server Detection**: Replaced import-based detection with AST instantiation checks for `FastMCP(...)` or `Server(...)` calls, preventing false server detections on pure import files.
- **Alias-Proof Network Detection**: Expanded network capability detection to cover all LLM client library calls (`google.generativeai`, `google.genai`, `openai`, `anthropic`, `aiohttp`, `boto3`, `azure`) and endpoint URL literals.
- **Tightened Secrets Rule**: Added high-confidence key-shape regexes (`sk-...`, `ghp_...`, `AKIA...`, `AIza...`, `xox...`) independent of variable names.
- **Context-Aware Database Severity**: Scoped `SELECT ... LIMIT/WHERE` queries are scored as **LOW**, unscoped `SELECT` as **MEDIUM`, and write operations or dynamic query formatting as **HIGH**.
- **Server-Level Combined Risk**: Extended combined risk rule to detect `database` + `network` and `database` + `execution` server capability combinations.
- **Deduplication**: Consolidated findings by `(category, tool_name, server_name)`, prioritizing code-based source locations with line numbers.

### Fixed
- Fixed finding duplication when servers are declared in both `mcp.json` and `server.py`.
- Fixed transport AST parsing for `mcp.run(transport=..., host=..., port=...)`.

---

## [0.1.0] - 2026-07-20

- Initial release of AgentShield static security scanner for MCP servers.
