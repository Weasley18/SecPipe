"""One merged SARIF run for GitHub code scanning.

GitHub rejects several runs from the same tool in one upload, so everything
goes into a single ``SecPipe`` run whose rule ids are ``<tool>/<rule>``.
Only blocking and warning findings are uploaded (capped), each with a stable
``partialFingerprints`` entry so alerts track across runs. Findings without a
file are anchored to the manifest that fixes them: requirements.txt for
dependencies, the Dockerfile for image CVEs. DAST findings have no source
location and appear in the PR comment and HTML report instead.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from secpipe import __version__
from secpipe.aggregator.gate import GateResult
from secpipe.aggregator.models import Finding, Severity

MAX_RESULTS = 1000
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}
LEVEL = {"block": "error", "warn": "warning"}


def _manifest_lines(root: Path | None) -> tuple[dict[str, tuple[str, int]], str | None]:
    """Map package name -> (requirements file, line); find the Dockerfile."""
    packages: dict[str, tuple[str, int]] = {}
    dockerfile: str | None = None
    if root is None or not root.is_dir():
        return packages, dockerfile
    for req in sorted(root.glob("**/requirements*.txt")):
        if any(part.startswith(".") or part in {"node_modules", "tests"} for part in req.relative_to(root).parts):
            continue
        for number, line in enumerate(req.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            match = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==", line)
            if match:
                name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
                packages.setdefault(name, (req.relative_to(root).as_posix(), number))
    for candidate in sorted(root.glob("**/Dockerfile")):
        rel = candidate.relative_to(root)
        if not any(part.startswith(".") for part in rel.parts):
            dockerfile = rel.as_posix()
            break
    return packages, dockerfile


def _location(finding: Finding, packages: dict[str, tuple[str, int]], dockerfile: str | None) -> tuple[str, int] | None:
    if finding.file and not finding.file.startswith("image:"):
        return finding.file, finding.line or 1
    if finding.package and finding.pkg_type != "os" and finding.package in packages:
        return packages[finding.package]
    if finding.category == "container" and dockerfile:
        return dockerfile, 1
    return None


def render(result: GateResult) -> dict[str, Any]:
    packages, dockerfile = _manifest_lines(result.options.source_root)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    # OS package CVEs are tracked by the container stage and a rollup Issue; as
    # code-scanning alerts on Dockerfile line 1 they would only be noise.
    selected = [f for f in result.findings if f.decision in LEVEL and f.pkg_type != "os"][:MAX_RESULTS]
    for finding in selected:
        where = _location(finding, packages, dockerfile)
        if where is None:
            continue
        rule_id = f"{finding.tool}/{finding.rule_id}"
        tags = ["security", finding.category] + ([finding.cwe] if finding.cwe else [])
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.title[:200] or finding.rule_id},
                "helpUri": finding.help_url or "https://github.com/Weasley18/SecPipe",
                "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY[finding.severity]},
            },
        )
        message = finding.title
        if finding.reasons:
            message += f" [{finding.decision}: {finding.reasons[-1]}]"
        if finding.also_reported_by:
            message += f" Also reported by: {', '.join(finding.also_reported_by)}."
        if finding.package:
            message += f" Package {finding.package} {finding.version or ''}".rstrip() + "."
            if finding.fix_version:
                message += f" Fixed in {finding.fix_version}."
        results.append(
            {
                "ruleId": rule_id,
                "level": LEVEL[finding.decision],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": where[0]},
                            "region": {"startLine": max(1, where[1])},
                        }
                    }
                ],
                "partialFingerprints": {"secpipe/v1": finding.fingerprint},
                "properties": {
                    "tool": finding.tool,
                    "category": finding.category,
                    "status": finding.status,
                    "cve": finding.cve,
                    "epss": finding.epss,
                    "in_kev": finding.in_kev,
                    "location": finding.location,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecPipe",
                        "informationUri": "https://github.com/Weasley18/SecPipe",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": f"secpipe/{result.options.stage}/"},
                "results": results,
            }
        ],
    }
