from agentshield.discovery.server_finder import find_servers
from agentshield.analysis.analyzer import analyze_servers
from agentshield.reporting.terminal import render_terminal_report
from rich.console import Console

skipped = []
servers = find_servers('tests/fixtures/', skipped=skipped)
findings, score = analyze_servers(servers)
c = Console()
render_terminal_report(servers, findings, score, console=c)
status = "FAIL" if findings else "PASS"
print(f"\n--- {status} | Servers: {len(servers)} | Findings: {len(findings)} | Score: {score} ---")
