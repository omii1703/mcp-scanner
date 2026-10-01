import os
from pathlib import Path
from typing import Dict, List, Tuple

from ..models.finding import SecurityFinding, SEVERITY_ORDER
from ..models.server import MCPServer
from .risk_scorer import apply_tool_risk_scores, compute_overall_score
from .rules import combined_risk, database, execution, filesystem, injection, llm_code_execution, network, secrets, transport

TOOL_RULES = [filesystem, execution, network, database, injection, llm_code_execution]
SERVER_RULES = [combined_risk, transport]

# Directories to skip during project-wide file walks (mirrors server_finder.EXCLUDED_DIRS)
_EXCLUDED_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".mypy_cache", ".pytest_cache", "site-packages",
    ".tox", "target", ".next", "coverage",
}

# Binary file extensions to skip during secrets scan
_BINARY_EXTS = {
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".lock",
}


def _read_source(file_path: str) -> str:
    try:
        return Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _deduplicate_findings(findings: List[SecurityFinding]) -> List[SecurityFinding]:
    """P6: Collapse duplicate findings by key.

    For secret findings, key includes source_file and source_line to preserve
    distinct secret findings across the project tree.
    For tool/server-level findings, key is (category, tool_name, server_name).
    """
    best: Dict[Tuple, SecurityFinding] = {}

    for finding in findings:
        if finding.category == "secrets":
            key = (finding.category, finding.source_file, finding.source_line)
        else:
            key = (finding.category, finding.tool_name, finding.server_name)

        existing = best.get(key)
        if existing is None:
            best[key] = finding
            continue

        # Prefer code-sourced (real line > 1) over manifest-sourced (line == 1)
        existing_is_code = existing.source_line > 1
        new_is_code = finding.source_line > 1

        if new_is_code and not existing_is_code:
            best[key] = finding
        elif existing_is_code and not new_is_code:
            pass  # keep existing
        else:
            # Both same type — keep higher severity
            if SEVERITY_ORDER.get(finding.severity, 4) < SEVERITY_ORDER.get(existing.severity, 4):
                best[key] = finding

    return list(best.values())


def _scan_project_for_secrets(root_path: str, servers: List[MCPServer] = None) -> List[SecurityFinding]:
    """P0 Fix 1: Walk the entire project tree and run the secrets rule on every
    text file, independent of whether an MCP server was detected in it.

    Respects _EXCLUDED_DIRS and skips known binary file extensions. Each
    finding carries the actual file path and a meaningful server_name: the
    real server name when the file belongs to a known MCP server, otherwise
    a "project-file:{filename}" sentinel so the terminal report shows a
    useful location instead of a blank "(server: )" field.
    """
    # Build a mapping from resolved file path -> server name for known servers.
    server_file_map: dict = {}
    if servers:
        for s in servers:
            try:
                server_file_map[str(Path(s.source_file).resolve())] = s.name
            except Exception:
                pass

    findings: List[SecurityFinding] = []
    root = Path(root_path).resolve()
    scanned: set = set()

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded and hidden directories in-place so os.walk won't descend
        dirnames[:] = [
            d for d in dirnames
            if d not in _EXCLUDED_DIRS and not d.startswith(".")
        ]
        for filename in filenames:
            file_path = Path(dirpath) / filename
            if file_path.suffix.lower() in _BINARY_EXTS:
                continue
            resolved = str(file_path.resolve())
            if resolved in scanned:
                continue
            scanned.add(resolved)
            try:
                source = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            # Use the real server name when possible; fall back to a readable
            # file-location sentinel so "(server: )" is never blank.
            sname = server_file_map.get(resolved, f"project-file:{Path(resolved).name}")
            findings.extend(secrets.analyze_file(resolved, source, server_name=sname))
    return findings


def analyze_servers(
    servers: List[MCPServer],
    root_path: str = "",
) -> Tuple[List[SecurityFinding], int]:
    findings: List[SecurityFinding] = []

    for server in servers:
        for tool in server.tools:
            for rule in TOOL_RULES:
                findings.extend(rule.analyze(tool, server))

        for rule in SERVER_RULES:
            findings.extend(rule.analyze(server))

    # P0 Fix 1: Project-wide secrets scan
    if root_path:
        findings.extend(_scan_project_for_secrets(root_path, servers=servers))
    else:
        scanned_files: set = set()
        for server in servers:
            if server.source_file in scanned_files:
                continue
            scanned_files.add(server.source_file)
            source = _read_source(server.source_file)
            if source:
                findings.extend(secrets.analyze_file(server.source_file, source, server.name))

    # Deduplicate findings
    findings = _deduplicate_findings(findings)

    findings.sort(key=lambda f: f.sort_key())

    apply_tool_risk_scores(servers, findings)
    overall_score = compute_overall_score(servers, findings)

    return findings, overall_score
