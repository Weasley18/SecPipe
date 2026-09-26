"""Diff against the base branch's findings (``findings.json`` from the last
green run on main) to label each finding new, existing or fixed."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding
from secpipe.aggregator.normalize import as_dict, as_list


@dataclass
class Baseline:
    findings: list[Finding]
    suppression_keys: set[str] = field(default_factory=set)
    commit: str | None = None
    generated_at: str | None = None


def load_baseline(path: Path | None) -> tuple[Baseline | None, list[str]]:
    """Return (baseline, warnings). A missing baseline is normal on the first
    run; an unreadable one is reported but treated as absent."""
    if path is None:
        return None, []
    if not path.exists():
        return None, [f"no baseline at {path}: every finding is treated as new"]
    try:
        data = as_dict(json.loads(path.read_text(encoding="utf-8")))
        findings = [
            Finding.from_dict(as_dict(item))
            for item in as_list(data.get("findings"))
            if as_dict(item).get("status") != "fixed"
        ]
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        return None, [f"baseline {path} is unreadable ({exc}); every finding is treated as new"]
    keys = {str(s.get("key")) for s in (as_dict(x) for x in as_list(data.get("suppressions"))) if s.get("key")}
    meta = as_dict(data.get("meta"))
    return Baseline(findings, keys, meta.get("commit"), meta.get("generated_at")), []


def _loose_key(finding: Finding) -> tuple[Any, ...]:
    """Line-insensitive identity for code findings, so an unrelated edit that
    shifts lines does not turn an old finding into a 'new' one."""
    if finding.file and finding.category in {"sast", "secret"}:
        return ("code", finding.tool, finding.rule_id, finding.file)
    return ("other", finding.category, finding.cve or finding.rule_id, finding.location)


def diff(current: list[Finding], baseline: Baseline | None) -> list[Finding]:
    """Set ``status`` on current findings and return the fixed ones."""
    if baseline is None:
        for finding in current:
            finding.status = "new"
        return []
    exact = {f.fingerprint: f for f in baseline.findings}
    loose: dict[tuple[Any, ...], list[Finding]] = defaultdict(list)
    for f in baseline.findings:
        loose[_loose_key(f)].append(f)
    matched: set[str] = set()
    unmatched: list[Finding] = []
    for finding in current:
        base = exact.get(finding.fingerprint)
        if base is not None and base.fingerprint not in matched:
            _mark_existing(finding, base, baseline, matched)
        else:
            unmatched.append(finding)
    for finding in unmatched:
        candidates = [b for b in loose.get(_loose_key(finding), []) if b.fingerprint not in matched]
        if candidates:
            _mark_existing(finding, candidates[0], baseline, matched)
        else:
            finding.status = "new"
    fixed = []
    for base in baseline.findings:
        if base.fingerprint not in matched:
            base.status = "fixed"
            base.decision = "fixed"
            base.reasons = ["no longer reported"]
            fixed.append(base)
    return fixed


def _mark_existing(finding: Finding, base: Finding, baseline: Baseline, matched: set[str]) -> None:
    finding.status = "existing"
    finding.first_seen = base.first_seen or baseline.generated_at
    matched.add(base.fingerprint)
