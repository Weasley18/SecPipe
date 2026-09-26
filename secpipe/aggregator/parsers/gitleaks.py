"""Gitleaks SARIF. Every result is critical; secret values are never stored."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import as_dict, as_str
from secpipe.aggregator.parsers.sarif import parse_sarif


def _customise(item: dict[str, Any], rule: dict[str, Any], finding: Finding) -> None:
    finding.severity = Severity.CRITICAL
    finding.raw_severity = "secret"
    finding.cwe = "CWE-798"
    finding.title = f"Secret detected ({finding.rule_id})"
    commit = as_str(as_dict(item.get("partialFingerprints")).get("commitSha"))[:12]
    where = f" in commit {commit}" if commit else ""
    finding.description = (
        f"Gitleaks rule {finding.rule_id} matched{where}. The value is redacted; "
        "revoke and rotate it, then purge it from history (docs/runbooks/leaked-secret.md)."
    )


def parse(path: Path) -> ParseResult:
    return parse_sarif(path, tool="gitleaks", category="secret", customise=_customise)
