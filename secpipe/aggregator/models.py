"""The normalised data model every parser produces and every reporter consumes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    def bump(self, levels: int = 1) -> Severity:
        return Severity(max(0, min(int(self) + levels, int(Severity.CRITICAL))))

    @classmethod
    def parse(cls, value: object, default: Severity | None = None) -> Severity:
        """Map any tool's severity word (or 0-4) onto the shared scale."""
        if isinstance(value, Severity):
            return value
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 4:
            return cls(value)
        key = str(value if value is not None else "").strip().lower()
        if key in _ALIASES:
            return _ALIASES[key]
        if default is None:
            raise ValueError(f"unknown severity {value!r}")
        return default

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """CVSS v3/v4 qualitative rating scale."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


_ALIASES: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "blocker": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "note": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "negligible": Severity.INFO,
    "none": Severity.INFO,
}

# category -> PR comment stage. K8s, cloud posture and pipeline config are all
# "infrastructure as code" from a developer's point of view.
STAGES: dict[str, str] = {
    "secret": "Secrets",  # nosec B105 -- category-to-stage display label, not a credential
    "sast": "SAST",
    "sca": "SCA",
    "container": "Container",
    "iac": "IaC",
    "k8s": "IaC",
    "cloud": "IaC",
    "dast": "DAST",
}
STAGE_ORDER = ["Secrets", "SAST", "SCA", "Container", "IaC", "DAST"]
# When one issue is reported under two categories, the more severe framing wins.
CATEGORY_PRIORITY = ["secret", "sca", "container", "sast", "iac", "k8s", "cloud", "dast"]

STATUSES = ("new", "existing", "fixed")
DECISIONS = ("block", "warn", "info", "excepted", "fixed")


@dataclass
class Finding:
    tool: str  # "trivy", "semgrep", ...
    category: str  # secret | sast | sca | container | iac | k8s | cloud | dast
    rule_id: str
    title: str
    severity: Severity
    location: str  # "app/src/auth.py:42", "pyyaml@5.3.1", "GET /notes/search"
    cve: str | None = None
    cwe: str | None = None
    fix_version: str | None = None
    epss: float | None = None
    in_kev: bool = False
    status: str = "new"  # new | existing | fixed
    also_reported_by: list[str] = field(default_factory=list)
    # ---- context used by dedupe, policy and reporters
    file: str | None = None
    line: int | None = None
    package: str | None = None
    version: str | None = None
    pkg_type: str | None = None  # python | os | ...
    fix_available: bool | None = None  # None: not a dependency finding
    cvss: float | None = None
    description: str = ""
    help_url: str | None = None
    raw_severity: str | None = None
    aliases: list[str] = field(default_factory=list)
    related_packages: list[str] = field(default_factory=list)
    direct: bool | None = None
    # ---- filled in by enrichment / policy
    severity_reasons: list[str] = field(default_factory=list)
    decision: str = "info"
    reasons: list[str] = field(default_factory=list)
    exception: dict[str, Any] | None = None
    first_seen: str | None = None
    due_date: str | None = None

    @property
    def fingerprint(self) -> str:
        key = f"{self.category}|{self.cve or self.rule_id}|{self.location}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def stage(self) -> str:
        return STAGES.get(self.category, "IaC")

    @property
    def tools(self) -> list[str]:
        return [self.tool, *self.also_reported_by]

    @property
    def advisory_ids(self) -> set[str]:
        ids = {a.upper() for a in self.aliases}
        if self.cve:
            ids.add(self.cve.upper())
        if self.category in ("sca", "container") and self.rule_id:
            ids.add(self.rule_id.upper())
        return ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "tool": self.tool,
            "category": self.category,
            "stage": self.stage,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "location": self.location,
            "cve": self.cve,
            "cwe": self.cwe,
            "fix_version": self.fix_version,
            "epss": self.epss,
            "in_kev": self.in_kev,
            "status": self.status,
            "also_reported_by": self.also_reported_by,
            "file": self.file,
            "line": self.line,
            "package": self.package,
            "version": self.version,
            "pkg_type": self.pkg_type,
            "fix_available": self.fix_available,
            "cvss": self.cvss,
            "description": self.description,
            "help_url": self.help_url,
            "raw_severity": self.raw_severity,
            "aliases": self.aliases,
            "related_packages": self.related_packages,
            "direct": self.direct,
            "severity_reasons": self.severity_reasons,
            "decision": self.decision,
            "reasons": self.reasons,
            "exception": self.exception,
            "first_seen": self.first_seen,
            "due_date": self.due_date,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            tool=str(data["tool"]),
            category=str(data["category"]),
            rule_id=str(data["rule_id"]),
            title=str(data.get("title", "")),
            severity=Severity.parse(data.get("severity"), Severity.MEDIUM),
            location=str(data.get("location", "")),
            cve=data.get("cve"),
            cwe=data.get("cwe"),
            fix_version=data.get("fix_version"),
            epss=data.get("epss"),
            in_kev=bool(data.get("in_kev", False)),
            status=str(data.get("status", "new")),
            also_reported_by=list(data.get("also_reported_by") or []),
            file=data.get("file"),
            line=data.get("line"),
            package=data.get("package"),
            version=data.get("version"),
            pkg_type=data.get("pkg_type"),
            fix_available=data.get("fix_available"),
            cvss=data.get("cvss"),
            description=str(data.get("description") or ""),
            help_url=data.get("help_url"),
            raw_severity=data.get("raw_severity"),
            aliases=list(data.get("aliases") or []),
            related_packages=list(data.get("related_packages") or []),
            direct=data.get("direct"),
            severity_reasons=list(data.get("severity_reasons") or []),
            decision=str(data.get("decision", "info")),
            reasons=list(data.get("reasons") or []),
            exception=data.get("exception"),
            first_seen=data.get("first_seen"),
            due_date=data.get("due_date"),
        )


@dataclass(frozen=True)
class LicenceRecord:
    package: str
    version: str
    licence: str  # as reported by the tool
    tool: str


@dataclass
class ParseResult:
    """What a parser returns. Parsers never raise on bad input: a report that
    cannot be read yields ``errors`` and the gate fails closed on it."""

    tool: str
    report: str
    findings: list[Finding] = field(default_factory=list)
    raw_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    suppressed: int = 0
    licences: list[LicenceRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors
