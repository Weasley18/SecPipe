"""Grype JSON, used by the nightly job to re-scan stored SBOMs."""

from __future__ import annotations

from pathlib import Path

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import (
    as_dict,
    as_float,
    as_list,
    as_str,
    clamp_text,
    find_cve,
    lowest_version,
    normalize_package,
    package_location,
)
from secpipe.aggregator.parsers.base import load_json

LANGUAGE_TYPES = {"python", "java-archive", "npm", "gem", "go-module", "rust-crate", "dotnet", "php-composer"}


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="grype", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    data = as_dict(data)
    if "matches" not in data:
        result.errors = [f"{path.name} is not a Grype JSON report"]
        return result
    seen: set[tuple[str, str, str]] = set()
    for match in as_list(data.get("matches")):
        match = as_dict(match)
        result.raw_count += 1
        vuln = as_dict(match.get("vulnerability"))
        artifact = as_dict(match.get("artifact"))
        vid = as_str(vuln.get("id"))
        related = [as_str(as_dict(r).get("id")) for r in as_list(match.get("relatedVulnerabilities"))]
        cve = find_cve(vid, *related)
        kind = as_str(artifact.get("type"))
        name = as_str(artifact.get("name"))
        name = normalize_package(name) if kind in LANGUAGE_TYPES else name
        version = as_str(artifact.get("version")) or None
        if (cve or vid, name, version or "") in seen:
            continue
        seen.add((cve or vid, name, version or ""))
        fix = as_dict(vuln.get("fix"))
        fix_version = lowest_version([as_str(v) for v in as_list(fix.get("versions"))])
        scores = [as_float(as_dict(c.get("metrics")).get("baseScore")) for c in map(as_dict, as_list(vuln.get("cvss")))]
        cvss = max((s for s in scores if s is not None), default=None)
        result.findings.append(
            Finding(
                tool="grype",
                category="sca" if kind in LANGUAGE_TYPES else "container",
                rule_id=cve or vid,
                title=f"{cve or vid} in {name}",
                severity=Severity.parse(vuln.get("severity"), Severity.MEDIUM),
                location=package_location(name, version),
                cve=cve,
                fix_version=fix_version,
                package=name,
                version=version,
                pkg_type="python" if kind == "python" else ("os" if kind in {"deb", "apk", "rpm"} else kind),
                fix_available=as_str(fix.get("state")) == "fixed" or fix_version is not None,
                cvss=cvss,
                description=clamp_text(as_str(vuln.get("description"))),
                aliases=sorted({vid, *related} - {cve or ""}),
                raw_severity=as_str(vuln.get("severity")).lower() or None,
                help_url=as_str(vuln.get("dataSource")) or None,
            )
        )
    return result
