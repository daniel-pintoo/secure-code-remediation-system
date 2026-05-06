from __future__ import annotations

from typing import Iterable, Mapping


SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

DEFAULT_SEVERITY_BY_TYPE = {
    "XSS": "high",
    "SQLi": "high",
    "SQL Injection": "high",
    "CommandInjection": "critical",
    "Command Injection": "critical",
    "PathTraversal": "high",
    "Path Traversal": "high",
    "SSRF": "high",
}


def vulnerability_base(vulnerability_id: str) -> str:
    """Return the stable vulnerability type from analyzer IDs such as SQLi_1."""
    parts = vulnerability_id.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return vulnerability_id


def severity_for(vulnerability_type: str) -> str:
    return DEFAULT_SEVERITY_BY_TYPE.get(vulnerability_type, "medium")


def severity_weight(severity: str) -> int:
    return SEVERITY_WEIGHTS.get(severity.lower(), SEVERITY_WEIGHTS["medium"])


def average_severity(vulnerabilities: Iterable[Mapping[str, object]]) -> float:
    items = list(vulnerabilities)
    if not items:
        return 0.0
    total = sum(severity_weight(str(item.get("severity", "medium"))) for item in items)
    return round(total / len(items), 2)


def vulnerability_score(vulnerabilities: Iterable[Mapping[str, object]]) -> int:
    return sum(severity_weight(str(item.get("severity", "medium"))) for item in vulnerabilities)


def improvement_percentage(initial_count: int, final_count: int) -> float:
    if initial_count <= 0:
        return 100.0 if final_count == 0 else 0.0
    fixed = max(initial_count - final_count, 0)
    return round((fixed / initial_count) * 100, 2)


def improved(new_vulnerabilities: Iterable[Mapping[str, object]], old_vulnerabilities: Iterable[Mapping[str, object]]) -> bool:
    old_items = list(old_vulnerabilities)
    new_items = list(new_vulnerabilities)
    return (len(new_items), vulnerability_score(new_items)) < (len(old_items), vulnerability_score(old_items))
