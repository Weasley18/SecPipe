"""Semgrep SARIF. Severity comes from the SARIF level; registry "secrets"
rules are categorised as secrets so the always-block policy applies."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult
from secpipe.aggregator.parsers.sarif import parse_sarif

_LOCAL_PREFIX = re.compile(r"^.*?policy\.semgrep\.")
RULES_URL = "https://github.com/Weasley18/SecPipe/blob/main/policy/semgrep"


def normalise_rule_id(rule_id: str) -> str:
    """Custom rules are prefixed with the config path Semgrep was given
    (``policy.semgrep.`` or ``.secpipe-tooling.policy.semgrep.``); strip it so
    fingerprints are stable wherever the tooling is checked out."""
    return _LOCAL_PREFIX.sub("", rule_id)


def _customise(item: dict[str, Any], rule: dict[str, Any], finding: Finding) -> None:
    rid = finding.rule_id.lower()
    tags = " ".join(str(t) for t in rule.get("properties", {}).get("tags", [])).lower()
    if ".secrets." in rid or "hardcoded-secret" in rid or ("detected-" in rid and "secret" in tags):
        finding.category = "secret"
    sentence = re.split(r"(?<=[.!?])\s", finding.description, maxsplit=1)[0].rstrip(".")
    name = finding.rule_id.rsplit(".", 1)[-1].replace("-", " ").capitalize()
    finding.title = sentence if 8 <= len(sentence) <= 110 else name
    if not finding.help_url and finding.rule_id.startswith("secnotes-"):
        finding.help_url = f"{RULES_URL}/{finding.rule_id.split('.')[-1]}.yaml"


def parse(path: Path) -> ParseResult:
    return parse_sarif(path, tool="semgrep", category="sast", rule_id=normalise_rule_id, customise=_customise)
