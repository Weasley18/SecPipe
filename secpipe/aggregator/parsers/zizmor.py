"""zizmor SARIF (GitHub Actions workflow security)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult
from secpipe.aggregator.normalize import clamp_text
from secpipe.aggregator.parsers.sarif import parse_sarif

WORKFLOWS = ".github/workflows/"


def _customise(item: dict[str, Any], rule: dict[str, Any], finding: Finding) -> None:
    finding.title = clamp_text(finding.description, 160) or finding.rule_id
    # zizmor reports paths relative to the directory it was given (.github/workflows).
    if finding.file and "/" not in finding.file:
        finding.file = WORKFLOWS + finding.file
        finding.location = f"{finding.file}:{finding.line}" if finding.line else finding.file


def parse(path: Path) -> ParseResult:
    return parse_sarif(path, tool="zizmor", category="iac", customise=_customise)
