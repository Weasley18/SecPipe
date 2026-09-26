"""Bandit JSON. Severity is combined with confidence: a LOW-confidence
result is downgraded one level, so noisy heuristics do not block merges."""

from __future__ import annotations

from pathlib import Path

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import (
    as_dict,
    as_int,
    as_list,
    as_str,
    clamp_text,
    code_location,
    normalize_path,
)
from secpipe.aggregator.parsers.base import load_json


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="bandit", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    data = as_dict(data)
    if "results" not in data:
        result.errors = [f"{path.name} is not a Bandit JSON report"]
        return result
    for err in as_list(data.get("errors")):
        result.warnings.append(f"bandit could not scan {as_str(as_dict(err).get('filename'))}")
    totals = as_dict(as_dict(data.get("metrics")).get("_totals"))
    result.suppressed = as_int(totals.get("nosec")) or 0
    for item in as_list(data.get("results")):
        item = as_dict(item)
        result.raw_count += 1
        severity = Severity.parse(item.get("issue_severity"), Severity.MEDIUM)
        confidence = as_str(item.get("issue_confidence")).upper()
        if confidence == "LOW":
            severity = max(Severity.LOW, severity.bump(-1))
        file = normalize_path(as_str(item.get("filename")))
        line = as_int(item.get("line_number"))
        cwe_id = as_int(as_dict(item.get("issue_cwe")).get("id"))
        result.findings.append(
            Finding(
                tool="bandit",
                category="sast",
                rule_id=as_str(item.get("test_id"), "B000"),
                title=clamp_text(as_str(item.get("issue_text")), 160),
                severity=severity,
                location=code_location(file, line),
                cwe=f"CWE-{cwe_id}" if cwe_id else None,
                file=file,
                line=line,
                description=clamp_text(
                    f"{as_str(item.get('test_name'))}: {as_str(item.get('issue_text'))} "
                    f"(confidence {confidence.lower() or 'unknown'})"
                ),
                help_url=as_str(item.get("more_info")) or None,
                raw_severity=f"{as_str(item.get('issue_severity')).lower()}/{confidence.lower()}",
            )
        )
    return result
