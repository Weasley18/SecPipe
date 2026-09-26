"""Shared SARIF 2.1.0 parser; tool modules supply severity and naming quirks."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import (
    as_dict,
    as_int,
    as_list,
    as_str,
    clamp_text,
    code_location,
    find_cwe,
    normalize_path,
)
from secpipe.aggregator.parsers.base import load_json

DEFAULT_LEVELS: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

# (result, rule) -> Finding field overrides
Customiser = Callable[[dict[str, Any], dict[str, Any], Finding], None]


def parse_sarif(
    path: Path,
    *,
    tool: str,
    category: str,
    levels: dict[str, Severity] | None = None,
    rule_id: Callable[[str], str] | None = None,
    customise: Customiser | None = None,
    roots: tuple[str, ...] = (),
) -> ParseResult:
    result = ParseResult(tool=tool, report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    runs = as_list(as_dict(data).get("runs"))
    if not isinstance(as_dict(data).get("runs"), list):
        result.errors = [f"{path.name} is not a SARIF log (no runs)"]
        return result
    level_map = levels or DEFAULT_LEVELS
    for run in runs:
        run = as_dict(run)
        for invocation in as_list(run.get("invocations")):
            invocation = as_dict(invocation)
            if invocation.get("executionSuccessful") is False:
                notes = [
                    as_str(as_dict(n.get("message")).get("text"))
                    for n in as_list(invocation.get("toolExecutionNotifications"))
                    if isinstance(n, dict) and n.get("level") == "error"
                ]
                result.errors.append(f"{tool} reported an unsuccessful run: {'; '.join(notes)[:300]}")
        driver = as_dict(as_dict(run.get("tool")).get("driver"))
        result.metadata.setdefault("version", driver.get("semanticVersion") or driver.get("version"))
        rules = [as_dict(r) for r in as_list(driver.get("rules"))]
        by_id = {as_str(r.get("id")): r for r in rules}
        for item in as_list(run.get("results")):
            item = as_dict(item)
            result.raw_count += 1
            if as_list(item.get("suppressions")):
                result.suppressed += 1
                continue
            rid = as_str(item.get("ruleId"))
            rule = by_id.get(rid)
            if rule is None:
                index = as_int(item.get("ruleIndex"))
                rule = rules[index] if index is not None and 0 <= index < len(rules) else {}
                rid = rid or as_str(rule.get("id"), "unknown")
            level = as_str(
                item.get("level") or as_dict(rule.get("defaultConfiguration")).get("level"), "warning"
            ).lower()
            physical = as_dict(as_dict((as_list(item.get("locations")) or [{}])[0]).get("physicalLocation"))
            uri = as_str(as_dict(physical.get("artifactLocation")).get("uri"))
            file = normalize_path(uri, roots) if uri else None
            line = as_int(as_dict(physical.get("region")).get("startLine"))
            props = as_dict(rule.get("properties"))
            message = as_str(as_dict(item.get("message")).get("text"))
            short = as_str(as_dict(rule.get("shortDescription")).get("text"))
            finding = Finding(
                tool=tool,
                category=category,
                rule_id=rule_id(rid) if rule_id else rid,
                title=clamp_text(short or message, 160),
                severity=level_map.get(level, Severity.MEDIUM),
                location=code_location(file, line) if file else rid,
                cwe=find_cwe(as_list(props.get("tags")), as_list(as_dict(item.get("properties")).get("tags"))),
                file=file,
                line=line,
                description=clamp_text(message),
                help_url=as_str(rule.get("helpUri")) or None,
                raw_severity=level,
            )
            if customise:
                customise(item, rule, finding)
            result.findings.append(finding)
    return result
