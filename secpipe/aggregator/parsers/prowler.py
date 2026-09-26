"""Prowler OCSF JSON (``-M json-ocsf``): cloud posture checks against the
Terraform-built AWS account."""

from __future__ import annotations

from pathlib import Path

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import as_dict, as_list, as_str, clamp_text
from secpipe.aggregator.parsers.base import load_json


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="prowler", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    if not isinstance(data, list):
        result.errors = [f"{path.name} is not a Prowler OCSF JSON list"]
        return result
    for item in data:
        item = as_dict(item)
        if as_str(item.get("status_code")).upper() != "FAIL":
            continue
        result.raw_count += 1
        info = as_dict(item.get("finding_info"))
        check = as_str(as_dict(item.get("metadata")).get("event_code")) or as_str(info.get("uid"))
        resources = [as_dict(r) for r in as_list(item.get("resources"))]
        resource = as_str(resources[0].get("uid")) if resources else "account"
        remediation = as_dict(item.get("remediation"))
        result.findings.append(
            Finding(
                tool="prowler",
                category="cloud",
                rule_id=check,
                title=clamp_text(as_str(info.get("title")) or check, 160),
                severity=Severity.parse(item.get("severity"), Severity.MEDIUM),
                location=resource,
                description=clamp_text(f"{as_str(item.get('message'))} {as_str(remediation.get('desc'))}"),
                raw_severity=as_str(item.get("severity")).lower() or None,
            )
        )
    return result
