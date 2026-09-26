"""SonarQube / SonarCloud Web API JSON: ``/api/issues/search`` (vulnerabilities)
and ``/api/hotspots/search`` (security hotspots still to review)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import as_dict, as_int, as_list, as_str, clamp_text, code_location
from secpipe.aggregator.parsers.base import load_json

LEGACY = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.HIGH,
    "MAJOR": Severity.MEDIUM,
    "MINOR": Severity.LOW,
    "INFO": Severity.INFO,
}


def _file(component: str) -> str:
    return component.split(":", 1)[1] if ":" in component else component


def _issue_severity(issue: dict[str, Any]) -> Severity:
    for impact in as_list(issue.get("impacts")):
        impact = as_dict(impact)
        if as_str(impact.get("softwareQuality")) == "SECURITY":
            return Severity.parse(as_str(impact.get("severity")), Severity.MEDIUM)
    return LEGACY.get(as_str(issue.get("severity")).upper(), Severity.MEDIUM)


def _is_security(issue: dict[str, Any]) -> bool:
    if as_str(issue.get("type")) in {"VULNERABILITY", "SECURITY_HOTSPOT"}:
        return True
    return any(as_str(as_dict(i).get("softwareQuality")) == "SECURITY" for i in as_list(issue.get("impacts")))


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="sonarqube", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    data = as_dict(data)
    if "issues" not in data and "hotspots" not in data:
        result.errors = [f"{path.name} is not a SonarQube issues/hotspots API response"]
        return result
    for issue in as_list(data.get("issues")):
        issue = as_dict(issue)
        if not _is_security(issue) or as_str(issue.get("status")) in {"CLOSED", "RESOLVED"}:
            continue
        result.raw_count += 1
        file = _file(as_str(issue.get("component")))
        line = as_int(issue.get("line"))
        result.findings.append(
            Finding(
                tool="sonarqube",
                category="sast",
                rule_id=as_str(issue.get("rule")),
                title=clamp_text(as_str(issue.get("message")), 160),
                severity=_issue_severity(issue),
                location=code_location(file, line),
                file=file,
                line=line,
                raw_severity=as_str(issue.get("severity")) or None,
            )
        )
    for hotspot in as_list(data.get("hotspots")):
        hotspot = as_dict(hotspot)
        if as_str(hotspot.get("status"), "TO_REVIEW") != "TO_REVIEW":
            continue
        result.raw_count += 1
        file = _file(as_str(hotspot.get("component")))
        line = as_int(hotspot.get("line"))
        result.findings.append(
            Finding(
                tool="sonarqube",
                category="sast",
                rule_id=as_str(hotspot.get("ruleKey") or hotspot.get("securityCategory")),
                title=clamp_text("Security hotspot: " + as_str(hotspot.get("message")), 160),
                severity=Severity.parse(hotspot.get("vulnerabilityProbability"), Severity.MEDIUM),
                location=code_location(file, line),
                file=file,
                line=line,
                raw_severity=f"hotspot/{as_str(hotspot.get('vulnerabilityProbability')).lower()}",
            )
        )
    return result
