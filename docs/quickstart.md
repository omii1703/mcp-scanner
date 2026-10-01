# AgentShield Quickstart

## Install

```bash
pip install -e .
```

(PyPI package `pip install agentshield` comes once this is published.)

## Scan a project

```bash
agentshield scan .
```

Point it at any codebase containing MCP servers — Python (`mcp` SDK) or
Node/TypeScript (`@modelcontextprotocol/sdk`), plus `mcp.json` /
`mcp.config.json` manifests and `mcpServers`-style client configs like
`claude_desktop_config.json`.

## Read the output

Each finding shows: severity, which tool/server it's on, what was
detected, and a one-line fix. The bottom line gives an overall score out
of 100 and a per-severity count.

Exit code tells you whether to fail a build: `0` clean, `1` findings
found, `2` the scan itself errored (bad path, unreadable files, etc).

## CI/CD

```bash
agentshield scan . --json -o report.json
```

Parse `report.json` in your pipeline; `findings[]` has full detail per
issue, `finding_counts` gives quick totals, `overall_score` for a
threshold gate.

## What it does NOT do (yet)

This is a static scanner — pattern matching on tool schemas, descriptions,
and source code. It doesn't run your agent, doesn't call any LLM, doesn't
monitor runtime behavior. That's intentional for v1: fast, deterministic,
zero API cost, explainable results. Runtime monitoring and auto-fix PRs
are later phases.
