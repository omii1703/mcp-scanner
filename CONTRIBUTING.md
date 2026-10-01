# Contributing to AgentShield

Thank you for your interest in contributing to **AgentShield**! AgentShield is an open-source security scanner designed to detect vulnerabilities, capabilities, and risks in Model Context Protocol (MCP) servers.

---

## Quickstart for Local Development

1. **Clone the repository:**
   `ash
   git clone https://github.com/agentshield/agentshield.git
   cd agentshield
   `

2. **Create a virtual environment and install in editable mode with dev dependencies:**
   `ash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e .[dev]
   `

3. **Run tests:**
   `ash
   pytest tests/ -v
   `

4. **Run AgentShield against local test fixtures:**
   `ash
   agentshield scan tests/fixtures/risky_server
   `

---

## Reporting False Positives & Missed Vulnerabilities

The single most valuable contribution right now is **testing AgentShield against real MCP servers** and reporting scanner accuracy issues!

If you find:
- **A false positive:** A tool parameter or code pattern wrongly flagged as dangerous (e.g. a conversational prompt parameter flagged as database access).
- **A missed vulnerability:** A dangerous pattern (e.g. unauthenticated network access, LLM-generated code execution) that AgentShield did not catch.

Please **[open a GitHub Issue](https://github.com/agentshield/agentshield/issues)** with:
1. The code snippet or manifest format.
2. What AgentShield reported (or missed).
3. What the expected behavior/score should be.

---

## Adding a New Detection Rule

1. Create a new module in src/agentshield/analysis/rules/your_rule.py.
2. Implement nalyze(tool: MCPTool, server: MCPServer) -> List[SecurityFinding].
3. Register the new rule in src/agentshield/analysis/analyzer.py under TOOL_RULES or SERVER_RULES.
4. Add comprehensive unit tests in 	ests/test_rules.py.
5. Run pytest tests/ to confirm all tests pass.

---

## Security Vulnerability Disclosure

If you discover a security vulnerability within **AgentShield's own codebase**, please do **NOT** create a public issue. Email security concerns privately to security@agentshield.dev (or open a GitHub Security Advisory).
