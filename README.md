# AgentShield 🛡️

[![CI](https://github.com/agentshield/agentshield/actions/workflows/ci.yml/badge.svg)](https://github.com/agentshield/agentshield/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/pypi/pyversions/agentshield.svg)](https://pypi.org/project/agentshield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AgentShield** is a fast, static security scanner for Model Context Protocol (MCP) servers that detects dangerous tool capabilities, credential leaks, unsanitised LLM execution sinks, and unsafe server configurations.

---

## ⚡ Quickstart

```bash
pip install agentshield
agentshield scan /path/to/mcp-server
```

---

## 🔒 Why AgentShield?

Model Context Protocol (MCP) servers give LLM agents rich capabilities to read files, run shell commands, query databases, and call external HTTP APIs. However, when LLM output flows into execution contexts or when servers expose overlapping capabilities without sandboxing, agents become vulnerable to data exfiltration, prompt injection, and remote code execution.

AgentShield inspects your MCP server source code and manifest files statically—without executing untrusted code—to calculate a security risk score and report actionable remediation steps before deployment.

---

## 📑 Coverage & Extensibility

AgentShield externalizes all capability hints, LLM SDK method tails, database access patterns, and execution sinks into a centralized pattern registry (`src/agentshield/patterns/registry.py`).

### Supported Integrations Today
- **LLM SDKs:** Google Gemini (`generate_content`), OpenAI (`chat.completions.create`), Anthropic (`messages.create`), LangChain (`.invoke`).
- **Database Libraries:** Raw SQL cursors (`cursor.execute`), SQLAlchemy ORM (`session.query`, `session.execute`), PyMongo NoSQL (`.find`, `.insert_one`), Django ORM (`.objects.filter`).
- **Execution & Shell:** `subprocess.run`, `os.system`, `os.popen`, `eval()`, `exec()`.
- **Network Clients:** `requests`, `httpx`, `urllib`, `fetch`, `axios`, `aiohttp`, AWS `boto3`, Azure SDK.

### Honest Coverage Guarantees
- **Unknown Capability Reporting:** If a tool calls into external libraries that AgentShield cannot classify, it is explicitly reported as **`Unknown capability (manual review recommended)`** rather than falsely reported as clean. Static analysis is transparent about its own boundaries.
- **Node/TypeScript Scanner Confidence:** Node.js MCP servers discovered via regex fallback are explicitly tagged as `node-mcp (regex-based, lower confidence)` in scan reports.

---

## 📊 Sample Terminal Output

```text
 AgentShield MCP Scan - 1 server, 6 tools discovered

 [CRITICAL] llm_code_execution  oee_assistant (server: cnc_assistant)
   -> LLM-generated output flows into cursor.execute without validation
   -> Fix: add a validation layer — parameterized queries, an allowlist, or sandboxed execution.

 [CRITICAL] secrets  (server: project-wide)
   -> Hardcoded credential/API key pattern detected ('sk-live-...')
   -> Fix: Move to an environment variable or secrets manager (e.g. os.environ['API_KEY'])

 Unknown capability (manual review recommended): cohere_agent
   -> Calls cohere_client.chat() in server.py, which the scanner could not classify (no recognized network/DB/execution pattern matched). This does NOT mean the tool is safe — it means static analysis couldn't determine its behavior.

 Clean (no findings): safe_read

 Overall MCP Security Score: 18/100
 Servers scanned: 1   Tools scanned: 6   Critical: 2   High: 0   Medium: 0   Low: 0
```

---

## 🎯 Detection Rule Categories

AgentShield evaluates your MCP servers across **9 security rule categories**:

| Category | Description | Default Severity |
| :--- | :--- | :--- |
| **`llm_code_execution`** | Untransformed LLM output flowing into `execute()`, `eval()`, `exec()`, or `subprocess.run()` | **CRITICAL** |
| **`secrets`** | Hardcoded API keys (`sk-...`, `ghp_...`, `AKIA...`) or passwords in source code | **CRITICAL** |
| **`combined_risk`** | Dangerous server capability combinations (e.g. `filesystem` + `network`, `execution` + `network`) | **CRITICAL / HIGH** |
| **`injection`** | Tool descriptions containing LLM system-prompt override language ("ignore previous instructions") | **CRITICAL** |
| **`execution`** | Unrestricted shell or subprocess execution without approval gates | **CRITICAL** |
| **`filesystem`** | Unrestricted read/write filesystem access without path allowlists or sandboxing | **HIGH** |
| **`network`** | Outbound HTTP requests or LLM API calls without domain allowlists | **HIGH** |
| **`database`** | Database queries lacking row-level restrictions or schema scoping | **LOW / MEDIUM / HIGH** |
| **`transport`** | Unauthenticated network transport (SSE/HTTP), disabled TLS, or `0.0.0.0` interface binding | **MEDIUM / HIGH** |

---

## 🛠️ CLI Usage & Flags

```bash
# Basic scan (terminal report output)
agentshield scan .

# Change output format (terminal, table, by-severity)
agentshield scan . --format table
agentshield scan . --format by-severity

# Output scan report as JSON
agentshield scan . --json

# Save scan output to a file
agentshield scan . --json --output report.json

# View CLI version
agentshield --version
```

### Exit Codes
- `0`: Scan completed cleanly with **zero security findings**.
- `1`: Scan completed and **found one or more security risks**.
- `2`: Invalid arguments, path does not exist, or runtime exception.

---

## 🔒 Platform vs. Static Security: Comparison Framing

**AgentShield** is a fast, zero-dependency static scanner you run before every commit or in CI — it is a complement to runtime/platform security tools, not a replacement for one. Because it does not run the server code, it cannot execute dynamic penetration tests or live prompt injections, but it acts as a lightweight gate to keep dangerous patterns, hardcoded secrets, and open transports out of production.

---

## 🛑 Known Limitations & SDK Coverage

Since AgentShield is a static tool, it relies on pattern lists matching standard framework classes and functions. Today's centralized registry covers:
- **LLM Client SDKs:** Google Gemini (`google-generativeai`), OpenAI Client, Anthropic SDK, LangChain Core.
- **Databases:** DB-API cursors, SQLAlchemy Engine/Session, PyMongo Client, Django ORM.
- **Network Clients:** `requests`, `httpx`, `urllib`, Node.js `fetch`/`axios`, AWS `boto3`.

Tools using library calls outside these frameworks will be marked as **`Unknown capability`** for manual review rather than defaulting to safe.

---

## 🛑 Non-Goals & Scope

To maintain fast execution, zero untrusted code execution, and high explainability, AgentShield explicitly does **NOT**:
- **Execute server code at runtime:** AgentShield uses AST parsing and static analysis; it never imports or executes scanned code.
- **Perform dynamic penetration testing:** It does not send live network payloads or attempt live prompt injections.
- **Replace full SAST tools:** AgentShield is purpose-built for agentic MCP server semantics, tool definitions, and LLM-agent risk surfaces.

---

## 🤝 Contributing & Development

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on setting up a local dev environment, running tests, and reporting false positives or adding pattern entries to `registry.py`.

---

## 📄 License

AgentShield is released under the [MIT License](LICENSE).
