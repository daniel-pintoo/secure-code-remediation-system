from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from py_analyzer import scan_code
from utils.scoring import average_severity, severity_for, vulnerability_base


@dataclass(frozen=True)
class ValidationResult:
    code: str
    raw_report: List[dict]
    vulnerabilities: List[dict]
    metrics: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerabilities": self.vulnerabilities,
            "metrics": self.metrics,
            "raw_analyzer_report": self.raw_report,
        }


def validate_code(code: str, patterns_path: str) -> ValidationResult:
    raw_report = scan_code(code, patterns_path)
    vulnerabilities = normalize_vulnerabilities(raw_report)
    metrics = {
        "vulnerability_count": len(vulnerabilities),
        "average_severity": average_severity(vulnerabilities),
    }
    return ValidationResult(
        code=code,
        raw_report=raw_report,
        vulnerabilities=vulnerabilities,
        metrics=metrics,
    )


def validate_file(code_path: str, patterns_path: str) -> ValidationResult:
    code = Path(code_path).read_text(encoding="utf-8")
    return validate_code(code, patterns_path)


def normalize_vulnerabilities(raw_report: List[dict]) -> List[dict]:
    """Convert analyzer flows into active vulnerabilities.

    The analyzer reports every taint flow and records sanitizers separately. For
    remediation validation, only flows that reached a sink without sanitization
    are counted as active vulnerabilities.
    """
    normalized: List[dict] = []
    for record in raw_report:
        unsanitized_flows = [
            flow for flow in record.get("flows", [])
            if len(flow) >= 2 and not flow[1]
        ]
        if not unsanitized_flows:
            continue

        vulnerability_id = str(record.get("vulnerability", "Unknown"))
        vulnerability_type = vulnerability_base(vulnerability_id)
        sink = record.get("sink", ["unknown", 0])
        source = record.get("source", ["unknown", 0])
        line = sink[1] if isinstance(sink, list) and len(sink) > 1 else 0
        source_name = source[0] if isinstance(source, list) and source else "unknown"
        sink_name = sink[0] if isinstance(sink, list) and sink else "unknown"

        normalized.append(
            {
                "id": vulnerability_id,
                "type": vulnerability_type,
                "line": line,
                "severity": severity_for(vulnerability_type),
                "description": (
                    f"Unsanitized input from '{source_name}' reaches sensitive sink "
                    f"'{sink_name}'."
                ),
                "source": source,
                "sink": sink,
                "flows": unsanitized_flows,
            }
        )
    return normalized


def write_report(path: str, report: Dict[str, Any]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
