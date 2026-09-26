"""OSV-Scanner v2 JSON. One finding per alias group per package; severity
from the group's max CVSS score, falling back to the database severity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult, Severity
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
    severity_or_cvss,
)
from secpipe.aggregator.parsers.base import load_json


def _fixed_versions(vuln: dict[str, Any], package: str) -> list[str]:
    fixed: list[str] = []
    for affected in as_list(vuln.get("affected")):
        affected = as_dict(affected)
        name = as_str(as_dict(affected.get("package")).get("name"))
        if name and normalize_package(name) != package:
            continue
        for rng in as_list(affected.get("ranges")):
            for event in as_list(as_dict(rng).get("events")):
                value = as_dict(event).get("fixed")
                if value:
                    fixed.append(as_str(value))
    return fixed


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="osv-scanner", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    data = as_dict(data)
    if "results" not in data:
        result.errors = [f"{path.name} is not an OSV-Scanner JSON report"]
        return result
    for source in as_list(data.get("results")):
        for pkg in as_list(as_dict(source).get("packages")):
            pkg = as_dict(pkg)
            meta = as_dict(pkg.get("package"))
            name = normalize_package(as_str(meta.get("name")))
            version = as_str(meta.get("version")) or None
            vulns = {as_str(v.get("id")): v for v in (as_dict(x) for x in as_list(pkg.get("vulnerabilities")))}
            result.raw_count += len(vulns)
            groups = [as_dict(g) for g in as_list(pkg.get("groups"))] or [
                {"ids": [vid], "aliases": as_list(v.get("aliases"))} for vid, v in vulns.items()
            ]
            for group in groups:
                ids = [as_str(i) for i in as_list(group.get("ids"))]
                aliases = sorted({*ids, *(as_str(a) for a in as_list(group.get("aliases")))})
                records = [vulns[i] for i in ids if i in vulns]
                primary = records[0] if records else {}
                cve = find_cve(*aliases)
                score = as_float(group.get("max_severity"))
                db_severity = next(
                    (
                        as_str(as_dict(r.get("database_specific")).get("severity"))
                        for r in records
                        if as_dict(r.get("database_specific")).get("severity")
                    ),
                    None,
                )
                fixed = [v for r in records for v in _fixed_versions(r, name)]
                fix = lowest_version(fixed)
                cwe = find_cwe(*(as_list(as_dict(r.get("database_specific")).get("cwe_ids")) for r in records))
                severity = Severity.from_cvss(score) if score else severity_or_cvss(db_severity, None)
                result.findings.append(
                    Finding(
                        tool="osv-scanner",
                        category="sca",
                        rule_id=cve or (ids[0] if ids else "OSV"),
                        title=clamp_text(as_str(primary.get("summary")) or f"{name}: {cve or ids[0]}", 160),
                        severity=severity,
                        location=package_location(name, version),
                        cve=cve,
                        cwe=cwe,
                        fix_version=fix,
                        package=name,
                        version=version,
                        pkg_type=as_str(meta.get("ecosystem")).lower() or None,
                        fix_available=fix is not None,
                        cvss=score,
                        description=clamp_text(as_str(primary.get("details") or primary.get("summary"))),
                        aliases=[a for a in aliases if a != cve],
                        raw_severity=str(score) if score else db_severity,
                        help_url=f"https://osv.dev/vulnerability/{ids[0]}" if ids else None,
                    )
                )
    return result
