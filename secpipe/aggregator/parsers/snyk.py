"""Snyk CLI JSON (``snyk test --json``). Gives dependency paths (direct vs
transitive) and licence issues."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, LicenceRecord, ParseResult, Severity
from secpipe.aggregator.normalize import (
    as_dict,
    as_float,
    as_list,
    as_str,
    clamp_text,
    find_cve,
    find_cwe,
    lowest_version,
    normalize_package,
    package_location,
)
from secpipe.aggregator.parsers.base import load_json


def _projects(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [as_dict(p) for p in data]
    return [as_dict(data)]


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="snyk", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    projects = _projects(data)
    if not any("vulnerabilities" in p or "ok" in p for p in projects):
        result.errors = [f"{path.name} is not a Snyk test JSON report"]
        return result
    for project in projects:
        if project.get("error"):
            result.errors.append(f"snyk: {as_str(project.get('error'))[:200]}")
            continue
        seen: set[tuple[str, str]] = set()
        for vuln in as_list(project.get("vulnerabilities")):
            vuln = as_dict(vuln)
            result.raw_count += 1
            name = normalize_package(as_str(vuln.get("packageName")))
            version = as_str(vuln.get("version")) or None
            if as_str(vuln.get("type")) == "license":
                result.licences.append(LicenceRecord(name, version or "", as_str(vuln.get("license")), "snyk"))
                continue
            vid = as_str(vuln.get("id"))
            if (vid, name) in seen:  # one entry per dependency path
                continue
            seen.add((vid, name))
            identifiers = as_dict(vuln.get("identifiers"))
            cve = find_cve(*(as_str(c) for c in as_list(identifiers.get("CVE"))))
            path_from = [as_str(p) for p in as_list(vuln.get("from"))]
            fix = lowest_version([as_str(v) for v in as_list(vuln.get("fixedIn"))])
            result.findings.append(
                Finding(
                    tool="snyk",
                    category="sca",
                    rule_id=cve or vid,
                    title=clamp_text(f"{as_str(vuln.get('title'))} in {name}", 160),
                    severity=Severity.parse(vuln.get("severity"), Severity.MEDIUM),
                    location=package_location(name, version),
                    cve=cve,
                    cwe=find_cwe(as_list(identifiers.get("CWE"))),
                    fix_version=fix,
                    package=name,
                    version=version,
                    pkg_type="python" if as_str(project.get("packageManager")) == "pip" else None,
                    fix_available=bool(vuln.get("isUpgradable") or vuln.get("isPatchable") or fix),
                    cvss=as_float(vuln.get("cvssScore")),
                    description=clamp_text(as_str(vuln.get("description"))),
                    aliases=[vid] if cve else [],
                    direct=len(path_from) == 2 if path_from else None,
                    raw_severity=as_str(vuln.get("severity")),
                    help_url=f"https://security.snyk.io/vuln/{vid}" if vid else None,
                )
            )
    return result
