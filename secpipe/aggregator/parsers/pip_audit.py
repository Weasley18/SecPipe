"""pip-audit JSON. pip-audit reports no severity, so findings default to
MEDIUM until deduplication merges them with a scanner that has CVSS data."""

from __future__ import annotations

from pathlib import Path

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import (
    as_dict,
    as_list,
    as_str,
    clamp_text,
    find_cve,
    lowest_version,
    normalize_package,
    package_location,
)
from secpipe.aggregator.parsers.base import load_json


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="pip-audit", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    data = as_dict(data)
    if "dependencies" not in data:
        result.errors = [f"{path.name} is not a pip-audit JSON report"]
        return result
    for dep in as_list(data.get("dependencies")):
        dep = as_dict(dep)
        name = normalize_package(as_str(dep.get("name")))
        version = as_str(dep.get("version")) or None
        seen: set[str] = set()
        for vuln in as_list(dep.get("vulns")):
            vuln = as_dict(vuln)
            vid = as_str(vuln.get("id"))
            result.raw_count += 1
            if vid in seen:
                continue
            seen.add(vid)
            aliases = [as_str(a) for a in as_list(vuln.get("aliases"))]
            cve = find_cve(*aliases, vid)
            fix = lowest_version([as_str(v) for v in as_list(vuln.get("fix_versions"))])
            result.findings.append(
                Finding(
                    tool="pip-audit",
                    category="sca",
                    rule_id=cve or vid,
                    title=f"{name} {version}: {cve or vid}",
                    severity=Severity.MEDIUM,
                    location=package_location(name, version),
                    cve=cve,
                    fix_version=fix,
                    package=name,
                    version=version,
                    pkg_type="python",
                    fix_available=fix is not None,
                    description=clamp_text(as_str(vuln.get("description"))),
                    aliases=sorted({vid, *aliases} - {cve or ""}),
                    raw_severity="unknown",
                    help_url=f"https://osv.dev/vulnerability/{vid}" if vid else None,
                )
            )
    return result
