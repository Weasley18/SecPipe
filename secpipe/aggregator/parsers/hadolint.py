"""Hadolint SARIF (Dockerfile lint)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import clamp_text
from secpipe.aggregator.parsers.sarif import parse_sarif

LEVELS = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW, "none": Severity.INFO}


def _customise(item: dict[str, Any], rule: dict[str, Any], finding: Finding) -> None:
    finding.title = clamp_text(finding.description, 160)
    finding.help_url = f"https://github.com/hadolint/hadolint/wiki/{finding.rule_id}"


def parse(path: Path) -> ParseResult:
    return parse_sarif(path, tool="hadolint", category="container", levels=LEVELS, customise=_customise)
