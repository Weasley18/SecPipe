"""OWASP ZAP JSON report (``-J``). One finding per alert per method + path;
the host and query values are stripped so findings are stable across runs."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import as_dict, as_int, as_list, as_str, clamp_text, find_cwe
from secpipe.aggregator.parsers.base import load_json

_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.IGNORECASE)
RISK = {0: Severity.INFO, 1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH}
FALSE_POSITIVE = "0"


def normalise_path(path: str) -> str:
    """Collapse ids so /notes/42 and /notes/77 are one endpoint: /notes/{id}."""
    return "/".join("{id}" if _ID_SEGMENT.match(part) else part for part in path.split("/")) or "/"


def _cwe(value: str) -> str | None:
    """ZAP reports a bare number; 0 and -1 mean "no CWE"."""
    number = as_int(value)
    return f"CWE-{number}" if number and number > 0 else find_cwe(value)


def _strip_tags(text: str) -> str:
    return text.replace("<p>", "").replace("</p>", " ").replace("<br>", " ")


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="zap", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    data = as_dict(data)
    if "site" not in data:
        result.errors = [f"{path.name} is not a ZAP JSON report"]
        return result
    result.metadata["version"] = data.get("@version")
    for site in as_list(data.get("site")):
        seen: set[tuple[str, str]] = set()
        for alert in as_list(as_dict(site).get("alerts")):
            alert = as_dict(alert)
            if as_str(alert.get("confidence")) == FALSE_POSITIVE:
                continue
            severity = RISK.get(as_int(alert.get("riskcode")) or 0, Severity.INFO)
            rule = as_str(alert.get("alertRef") or alert.get("pluginid"))
            instances = as_list(alert.get("instances")) or [{}]
            for instance in instances:
                instance = as_dict(instance)
                result.raw_count += 1
                method = as_str(instance.get("method"), "GET").upper()
                url_path = normalise_path(urlsplit(as_str(instance.get("uri"))).path or "/")
                location = f"{method} {url_path}"
                if (rule, location) in seen:
                    continue
                seen.add((rule, location))
                param = as_str(instance.get("param"))
                result.findings.append(
                    Finding(
                        tool="zap",
                        category="dast",
                        rule_id=f"zap-{rule}",
                        title=clamp_text(as_str(alert.get("name") or alert.get("alert")), 160),
                        severity=severity,
                        location=location,
                        cwe=_cwe(as_str(alert.get("cweid"))),
                        description=clamp_text(
                            _strip_tags(as_str(alert.get("desc")))
                            + (f" Parameter: {param}." if param else "")
                            + f" Solution: {_strip_tags(as_str(alert.get('solution')))}"
                        ),
                        help_url=f"https://www.zaproxy.org/docs/alerts/{as_str(alert.get('pluginid'))}/",
                        raw_severity=as_str(alert.get("riskdesc")) or None,
                    )
                )
    return result
