"""policy.yaml: loading, JSON Schema validation and evaluation."""

from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from secpipe.aggregator.models import Finding, LicenceRecord, Severity
from secpipe.aggregator.normalize import as_dict, as_list, as_str, normalize_package, package_location

APPROVAL_LABEL = "secpipe:suppressions-approved"


class PolicyError(Exception):
    """policy.yaml is missing, unparsable or fails schema validation."""


@dataclass(frozen=True)
class Rules:
    block_at_or_above: Severity = Severity.HIGH
    warn_at_or_above: Severity = Severity.MEDIUM
    always_block_categories: tuple[str, ...] = ("secret",)
    block_if_in_kev: bool = True
    epss_bump_threshold: float = 0.1
    no_fix_available: str = "warn"
    only_new_findings_block_prs: bool = True
    max_suppressions_per_pr: int = 3
    exception_warning_days: int = 14

    def merged(self, overrides: dict[str, Any]) -> Rules:
        values: dict[str, Any] = {}
        for key, value in overrides.items():
            if key in {"block_at_or_above", "warn_at_or_above"}:
                values[key] = Severity.parse(value)
            elif key == "always_block_categories":
                values[key] = tuple(value)
            else:
                values[key] = value
        return replace(self, **values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_at_or_above": self.block_at_or_above.label,
            "warn_at_or_above": self.warn_at_or_above.label,
            "always_block_categories": list(self.always_block_categories),
            "block_if_in_kev": self.block_if_in_kev,
            "epss_bump_threshold": self.epss_bump_threshold,
            "no_fix_available": self.no_fix_available,
            "only_new_findings_block_prs": self.only_new_findings_block_prs,
            "max_suppressions_per_pr": self.max_suppressions_per_pr,
            "exception_warning_days": self.exception_warning_days,
        }


@dataclass(frozen=True)
class PolicyException:
    reason: str
    owner: str
    expires: dt.date
    fingerprint: str | None = None
    rule: str | None = None
    path: str | None = None
    tool: str | None = None
    ticket: str | None = None

    @property
    def label(self) -> str:
        label = self.fingerprint or f"{self.rule}{'@' + self.path if self.path else ''}"
        return f"{self.tool}:{label}" if self.tool else label

    def matches(self, finding: Finding) -> bool:
        if self.tool and self.tool not in finding.tools:
            return False
        if self.fingerprint:
            return finding.fingerprint == self.fingerprint
        if self.rule and finding.rule_id != self.rule and not finding.rule_id.endswith("." + self.rule):
            return False
        if self.path:
            return fnmatch.fnmatch(finding.file or finding.location, self.path)
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule": self.rule,
            "path": self.path,
            "tool": self.tool,
            "reason": self.reason,
            "owner": self.owner,
            "expires": self.expires.isoformat(),
            "ticket": self.ticket,
        }


@dataclass(frozen=True)
class SeverityOverride:
    rule: str
    severity: Severity
    reason: str
    tool: str | None = None

    def matches(self, finding: Finding) -> bool:
        if self.tool and self.tool not in finding.tools:
            return False
        return finding.rule_id == self.rule or finding.rule_id.endswith("." + self.rule)


@dataclass
class Policy:
    defaults: Rules
    branches: dict[str, dict[str, Any]]
    licence_deny: tuple[str, ...]
    licence_allow: tuple[str, ...]
    licence_unknown: str
    sla_days: dict[str, int]
    exceptions: list[PolicyException]
    severity_overrides: list[SeverityOverride]
    source: str = "policy.yaml"
    digest: str = ""

    @classmethod
    def load(cls, path: Path) -> Policy:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PolicyError(f"cannot read policy {path}: {exc.strerror or exc}") from exc
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise PolicyError(f"{path} is not valid YAML: {exc}") from exc
        data = _stringify_dates(data)
        validate(data, str(path))
        policy = cls.from_dict(as_dict(data))
        policy.source = path.name
        policy.digest = hashlib.sha256(raw).hexdigest()[:7]
        return policy

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        defaults = Rules().merged(as_dict(data.get("defaults")))
        licences = as_dict(data.get("licences"))
        return cls(
            defaults=defaults,
            branches={str(k): as_dict(v) for k, v in as_dict(data.get("branches")).items()},
            licence_deny=tuple(as_str(x) for x in as_list(licences.get("deny"))),
            licence_allow=tuple(as_str(x) for x in as_list(licences.get("allow"))),
            licence_unknown=as_str(licences.get("unknown"), "warn"),
            sla_days={str(k): int(v) for k, v in as_dict(data.get("sla_days")).items()},
            exceptions=[
                PolicyException(
                    reason=as_str(e.get("reason")),
                    owner=as_str(e.get("owner")),
                    expires=dt.date.fromisoformat(as_str(e.get("expires"))),
                    fingerprint=e.get("fingerprint"),
                    rule=e.get("rule"),
                    path=e.get("path"),
                    tool=e.get("tool"),
                    ticket=e.get("ticket"),
                )
                for e in (as_dict(x) for x in as_list(data.get("exceptions")))
            ],
            severity_overrides=[
                SeverityOverride(
                    rule=as_str(o.get("rule")),
                    severity=Severity.parse(o.get("severity")),
                    reason=as_str(o.get("reason")),
                    tool=o.get("tool"),
                )
                for o in (as_dict(x) for x in as_list(data.get("severity_overrides")))
            ],
        )

    def rules_for(self, branch: str | None) -> Rules:
        rules = self.defaults
        if not branch:
            return rules
        for pattern, overrides in self.branches.items():
            if fnmatch.fnmatch(branch, pattern):
                rules = rules.merged(overrides)
        return rules


def _stringify_dates(value: Any) -> Any:
    """YAML turns 2026-12-31 into a date; the schema validates ISO strings."""
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _stringify_dates(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stringify_dates(v) for v in value]
    return value


def schema() -> dict[str, Any]:
    text = resources.files("secpipe.aggregator").joinpath("policy.schema.json").read_text(encoding="utf-8")
    loaded: dict[str, Any] = json.loads(text)
    return loaded


def validate(data: Any, source: str = "policy.yaml") -> None:
    validator = jsonschema.Draft202012Validator(schema(), format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    if errors:
        lines = [f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}" for e in errors]
        raise PolicyError(f"{source} failed schema validation:\n  " + "\n  ".join(lines))
    rules = as_dict(as_dict(data).get("defaults"))
    if Severity.parse(rules.get("warn_at_or_above")) > Severity.parse(rules.get("block_at_or_above")):
        raise PolicyError(f"{source}: warn_at_or_above must not be above block_at_or_above")


# ------------------------------------------------------------------ licences
_CLASSIFIERS: dict[str, str] = {
    "mit license": "MIT",
    "mit": "MIT",
    "bsd license": "BSD",
    "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
    "isc license (iscl)": "ISC",
    "the unlicense (unlicense)": "Unlicense",
    "gnu affero general public license v3": "AGPL-3.0",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.1",
    "server side public license": "SSPL-1.0",
}
_SPDX_SUFFIX = re.compile(r"-(only|or-later)$|\+$", re.IGNORECASE)


def normalise_licence(value: str) -> str:
    text = value.strip()
    mapped = _CLASSIFIERS.get(text.lower())
    if mapped:
        return mapped
    return _SPDX_SUFFIX.sub("", text) or "UNKNOWN"


def _licence_terms(expression: str) -> tuple[str, list[str]]:
    """('any'|'all', [ids]) for an SPDX-ish expression."""
    if re.search(r"\s+OR\s+", expression):
        return "any", [normalise_licence(p) for p in re.split(r"\s+OR\s+", expression.strip("() "))]
    if re.search(r"\s+AND\s+", expression):
        return "all", [normalise_licence(p) for p in re.split(r"\s+AND\s+", expression.strip("() "))]
    return "all", [normalise_licence(expression)]


def _matches(licence: str, patterns: tuple[str, ...]) -> bool:
    return any(licence.lower() == p.lower() or licence.lower().startswith(p.lower() + "-") for p in patterns)


def _licence_finding(
    record: LicenceRecord,
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    reasons: list[str] | None = None,
) -> Finding:
    package = normalize_package(record.package)
    return Finding(
        tool=record.tool,
        category="sca",
        rule_id=rule_id,
        title=title,
        severity=severity,
        location=package_location(package, record.version or None),
        package=package,
        version=record.version or None,
        description=description,
        raw_severity=record.licence,
        reasons=list(reasons or []),
    )


def evaluate_licences(records: list[LicenceRecord], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for record in sorted(records, key=lambda r: (r.package, r.tool)):
        if record.package in seen:
            continue
        seen.add(record.package)
        mode, terms = _licence_terms(record.licence or "UNKNOWN")
        denied = [t for t in terms if _matches(t, policy.licence_deny)]
        unknown = all(t.upper() == "UNKNOWN" for t in terms)
        allowed = [t for t in terms if _matches(t, policy.licence_allow)] if policy.licence_allow else terms
        is_denied = (len(denied) == len(terms)) if mode == "any" else bool(denied)
        if is_denied:
            findings.append(
                _licence_finding(
                    record,
                    rule_id=f"licence-denied:{denied[0]}",
                    title=f"Denied licence {record.licence} in {record.package}",
                    severity=Severity.CRITICAL,
                    description=f"{record.package} {record.version} is licensed {record.licence}, "
                    "which policy.yaml denies. Replace the dependency or obtain a legal exception.",
                )
            )
        elif unknown and policy.licence_unknown != "ignore":
            findings.append(
                _licence_finding(
                    record,
                    rule_id="licence-unknown",
                    title=f"Unknown licence for {record.package}",
                    severity=Severity.HIGH if policy.licence_unknown == "block" else Severity.LOW,
                    description="The licence could not be determined; review it manually.",
                    reasons=[f"licence policy: unknown -> {policy.licence_unknown}"],
                )
            )
        elif policy.licence_allow and not unknown and (not allowed if mode == "all" else not any(allowed)):
            findings.append(
                _licence_finding(
                    record,
                    rule_id=f"licence-not-allowed:{terms[0]}",
                    title=f"Licence {record.licence} for {record.package} is not on the allow-list",
                    severity=Severity.LOW,
                    description="Not denied, but not pre-approved either; review before shipping.",
                )
            )
    return findings


# ---------------------------------------------------------------- evaluation
@dataclass
class Evaluation:
    rules: Rules
    blocking: list[Finding] = field(default_factory=list)
    gate_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    expired_exceptions: list[PolicyException] = field(default_factory=list)
    expiring_exceptions: list[PolicyException] = field(default_factory=list)
    active_exceptions: list[PolicyException] = field(default_factory=list)
    new_suppressions: int = 0
    suppression_cap_exceeded: bool = False

    @property
    def passed(self) -> bool:
        return not self.blocking and not self.gate_errors


def evaluate(
    findings: list[Finding],
    policy: Policy,
    *,
    branch: str | None,
    event: str,
    today: dt.date,
    new_suppressions: int = 0,
    labels: tuple[str, ...] = (),
    tools_run: frozenset[str] | None = None,
) -> Evaluation:
    rules = policy.rules_for(branch)
    result = Evaluation(rules=rules, new_suppressions=new_suppressions)
    is_pr = event in {"pull_request", "pull_request_target", "merge_group"}

    for exc in policy.exceptions:
        if exc.expires < today:
            result.expired_exceptions.append(exc)
            result.gate_errors.append(
                f"exception {exc.label} (owner {exc.owner}) expired on {exc.expires.isoformat()}: renew or remove it"
            )
        else:
            result.active_exceptions.append(exc)
            if (exc.expires - today).days <= rules.exception_warning_days:
                result.expiring_exceptions.append(exc)
                result.warnings.append(f"exception {exc.label} expires on {exc.expires.isoformat()}")
    used: set[str] = set()

    for finding in findings:
        finding.reasons = [r for r in finding.reasons if r.startswith("licence policy")]
        for override in policy.severity_overrides:
            if override.matches(finding) and finding.severity != override.severity:
                finding.severity_reasons.append(
                    f"policy override {finding.severity.label} -> {override.severity.label}: {override.reason}"
                )
                finding.severity = override.severity
                break
        if finding.epss is not None and finding.epss > rules.epss_bump_threshold:
            bumped = finding.severity.bump()
            if bumped != finding.severity:
                finding.severity_reasons.append(
                    f"EPSS {finding.epss:.3f} > {rules.epss_bump_threshold}: {finding.severity.label} -> {bumped.label}"
                )
                finding.severity = bumped
        if finding.in_kev and finding.severity != Severity.CRITICAL:
            finding.severity_reasons.append(f"in CISA KEV: {finding.severity.label} -> critical")
            finding.severity = Severity.CRITICAL

        matched = next((e for e in result.active_exceptions if e.matches(finding)), None)
        if matched is not None:
            used.add(matched.label)
            finding.decision = "excepted"
            finding.exception = matched.to_dict()
            finding.reasons.append(f"accepted until {matched.expires.isoformat()} by {matched.owner}: {matched.reason}")
            continue
        finding.decision, reason = _decide(finding, rules, is_pr)
        if reason:
            finding.reasons.append(reason)
        if finding.decision == "block":
            result.blocking.append(finding)

    for exc in result.active_exceptions:
        # An exception scoped to a scanner that did not run in this gate (Grype
        # runs nightly only) has nothing to match, which says nothing about it.
        if exc.tool and tools_run is not None and exc.tool not in tools_run:
            continue
        if exc.label not in used:
            result.warnings.append(f"exception {exc.label} matched no finding: remove it")

    cap = rules.max_suppressions_per_pr
    if is_pr and new_suppressions > cap:
        if APPROVAL_LABEL in labels:
            result.warnings.append(
                f"{new_suppressions} new suppressions (cap {cap}) approved via the '{APPROVAL_LABEL}' label"
            )
        else:
            result.suppression_cap_exceeded = True
            result.gate_errors.append(
                f"{new_suppressions} new suppressions exceed the cap of {cap}: a CODEOWNER must review them "
                f"and add the '{APPROVAL_LABEL}' label"
            )
    return result


def _decide(finding: Finding, rules: Rules, is_pr: bool) -> tuple[str, str]:
    if finding.category in rules.always_block_categories:
        return "block", f"category '{finding.category}' always blocks"
    if finding.in_kev and rules.block_if_in_kev:
        return "block", "known exploited (CISA KEV)"
    if any(r.startswith("licence policy: unknown -> warn") for r in finding.reasons):
        return "warn", ""
    if finding.severity >= rules.block_at_or_above:
        if finding.fix_available is False and rules.no_fix_available == "warn":
            return "warn", "no fix available upstream: tracked, not blocking"
        if is_pr and rules.only_new_findings_block_prs and finding.status == "existing":
            return "warn", "already present on the base branch"
        return "block", f"{finding.severity.label} >= {rules.block_at_or_above.label}"
    if finding.severity >= rules.warn_at_or_above:
        return "warn", f"{finding.severity.label} >= {rules.warn_at_or_above.label}"
    return "info", ""


def due_date(finding: Finding, policy: Policy, today: dt.date) -> str | None:
    days = policy.sla_days.get(finding.severity.label)
    if not days:
        return None
    start = dt.date.fromisoformat(finding.first_seen[:10]) if finding.first_seen else today
    return (start + dt.timedelta(days=days)).isoformat()
