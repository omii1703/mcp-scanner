SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "dim white",
}

SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def severity_style(severity: str) -> str:
    return SEVERITY_STYLES.get(severity, "white")


def severity_label(severity: str) -> str:
    return SEVERITY_LABELS.get(severity, severity.upper())


def score_style(score: int) -> str:
    if score >= 85:
        return "bold green"
    if score >= 60:
        return "bold yellow"
    return "bold red"
