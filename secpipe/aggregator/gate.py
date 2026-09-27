"""The gate: collect -> parse -> check expected tools (fail closed) -> licences
-> suppressions -> dedupe -> enrich -> baseline diff -> policy -> outputs.

Exit codes: 0 pass, 1 blocked by policy, 2 tool or configuration error.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secpipe import __version__
from secpipe.aggregator.baseline import Baseline, diff, load_baseline
from secpipe.aggregator.dedupe import DedupeStats, deduplicate
from secpipe.aggregator.enrich import EnrichmentReport, ThreatIntel
from secpipe.aggregator.models import STAGE_ORDER, Finding, ParseResult, Severity
from secpipe.aggregator.normalize import as_dict, as_float, as_int, as_str
from secpipe.aggregator.parsers import spec_for
from secpipe.aggregator.policy import (
    Evaluation,
    Policy,
    PolicyError,
    Rules,
    due_date,
    evaluate,
    evaluate_licences,
)
from secpipe.aggregator.suppressions import Suppression, scan, unjustified_findings

EXIT_PASS, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2

TOOL_STAGE: dict[str, str] = {
    "gitleaks": "Secrets",
    "semgrep": "SAST",
    "bandit": "SAST",
    "sonarqube": "SAST",
    "snyk": "SCA",
    "osv-scanner": "SCA",
    "pip-audit": "SCA",
    "pip-licenses": "SCA",
    "trivy-image": "Container",
    "hadolint": "Container",
    "syft": "Container",
    "grype": "Container",
    "checkov-dockerfile": "Container",
    "trivy-iac": "IaC",
    "checkov": "IaC",
    "kubescape": "IaC",
    "zizmor": "IaC",
    "prowler": "IaC",
    "zap": "DAST",
}


def stage_of_run(name: str, parser: str | None) -> str:
    for key in (name, parser or ""):
        if key in TOOL_STAGE:
            return TOOL_STAGE[key]
    for prefix, stage in TOOL_STAGE.items():
        if name.startswith(prefix):
            return stage
    return "IaC"


@dataclass
class ToolRun:
    name: str
    parser: str | None
    report: str | None
    status: str  # ok | error | skipped
    duration: float | None = None
    version: str | None = None
    exit_code: int | None = None
    raw: int = 0
    findings: int = 0
    suppressed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def stage(self) -> str:
        return stage_of_run(self.name, self.parser)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "parser": self.parser,
            "report": self.report,
            "status": self.status,
            "stage": self.stage,
            "duration_seconds": self.duration,
            "version": self.version,
            "exit_code": self.exit_code,
            "raw_results": self.raw,
            "findings": self.findings,
            "suppressed": self.suppressed,
            "errors": self.errors,
        }


@dataclass
class StageSummary:
    name: str
    result: str = "pass"  # pass | warn | fail | error | pending | skipped
    new: int = 0
    existing: int = 0
    fixed: int = 0
    blocking: int = 0
    warnings: int = 0
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "result": self.result,
            "new": self.new,
            "existing": self.existing,
            "fixed": self.fixed,
            "blocking": self.blocking,
            "warnings": self.warnings,
            "tools": self.tools,
        }


@dataclass
class GateOptions:
    reports: Path
    policy: Path
    expect: list[str] = field(default_factory=list)
    branch: str | None = None
    event: str = "push"
    baseline: Path | None = None
    out: Path | None = None
    stage: str = "gate"
    source_root: Path | None = None
    offline: bool = False
    cache_dir: Path = Path(".secpipe-cache")
    labels: tuple[str, ...] = ()
    today: dt.date | None = None
    commit: str | None = None
    policy_ref: str | None = None
    run_url: str | None = None
    repository: str | None = None
    intel: ThreatIntel | None = None


@dataclass
class GateResult:
    options: GateOptions
    outcome: str
    exit_code: int
    findings: list[Finding]
    fixed: list[Finding]
    runs: list[ToolRun]
    tool_errors: list[str]
    dedupe: DedupeStats
    enrichment: EnrichmentReport
    suppressions: list[Suppression]
    evaluation: Evaluation
    stages: dict[str, StageSummary]
    warnings: list[str]
    policy_ref: str
    generated_at: str
    sla_days: dict[str, int] = field(default_factory=dict)

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.decision == "block"]

    @property
    def warned(self) -> list[Finding]:
        return [f for f in self.findings if f.decision == "warn"]

    @property
    def excepted(self) -> list[Finding]:
        return [f for f in self.findings if f.decision == "excepted"]

    @property
    def rules(self) -> Rules:
        return self.evaluation.rules

    def counts(self, decision: str | None = None) -> dict[str, int]:
        selected = [f for f in self.findings if decision is None or f.decision == decision]
        return {s.label: sum(1 for f in selected if f.severity == s) for s in reversed(Severity)}

    def summary(self) -> dict[str, Any]:
        opts = self.options
        return {
            "stage": opts.stage,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "branch": opts.branch,
            "event": opts.event,
            "commit": opts.commit,
            "repository": opts.repository,
            "run_url": opts.run_url,
            "generated_at": self.generated_at,
            "secpipe_version": __version__,
            "policy": {"file": opts.policy.as_posix(), "ref": self.policy_ref, "rules": self.rules.to_dict()},
            "counts": {
                "raw_results": self.dedupe.raw,
                "unique_findings": self.dedupe.unique,
                "deduplicated": self.dedupe.removed,
                "blocking": len(self.blocking),
                "warnings": len(self.warned),
                "excepted": len(self.excepted),
                "new": sum(1 for f in self.findings if f.status == "new"),
                "existing": sum(1 for f in self.findings if f.status == "existing"),
                "fixed": len(self.fixed),
                "by_severity": self.counts(),
                "blocking_by_severity": self.counts("block"),
            },
            "stages": {name: s.to_dict() for name, s in self.stages.items()},
            "tools": [r.to_dict() for r in self.runs],
            "tool_errors": self.tool_errors,
            "gate_errors": self.evaluation.gate_errors,
            "warnings": self.warnings,
            "suppressions": {
                "total": len(self.suppressions),
                "new": self.evaluation.new_suppressions,
                "cap": self.rules.max_suppressions_per_pr,
                "unjustified": sum(1 for s in self.suppressions if not s.justified),
            },
            "exceptions": {
                "active": len(self.evaluation.active_exceptions),
                "expiring_soon": [e.to_dict() for e in self.evaluation.expiring_exceptions],
                "expired": [e.to_dict() for e in self.evaluation.expired_exceptions],
            },
            "enrichment": {
                "kev_available": self.enrichment.kev_available,
                "epss_available": self.enrichment.epss_available,
                "cves": self.enrichment.cves,
                "in_kev": self.enrichment.in_kev,
                "epss_scored": self.enrichment.epss_scored,
                "errors": self.enrichment.errors,
            },
        }


def _read_meta(path: Path) -> dict[str, Any]:
    try:
        return as_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return {}


def collect(reports: Path) -> tuple[list[ToolRun], list[ParseResult]]:
    """Parse every report under ``reports`` and pair it with its meta sidecar."""
    metas = {as_str(m.get("tool")): m for m in (_read_meta(p) for p in sorted(reports.rglob("*.meta.json"))) if m}
    by_report = {as_str(m.get("report")): name for name, m in metas.items() if m.get("report")}
    runs: dict[str, ToolRun] = {}
    parsed: list[ParseResult] = []
    for path in sorted(p for p in reports.rglob("*") if p.is_file()):
        spec = spec_for(path)
        if spec is None:
            continue
        result = spec.parse(path)
        parsed.append(result)
        name = by_report.get(path.name, path.stem)
        meta = metas.get(name, {})
        status = as_str(meta.get("status"), "ok")
        errors = list(result.errors)
        if status == "error":
            errors.insert(0, as_str(meta.get("reason")) or f"scanner exited with {meta.get('exit_code')}")
        runs[name] = ToolRun(
            name=name,
            parser=spec.tool,
            report=path.name,
            status="error" if errors else "ok",
            duration=as_float(meta.get("duration_seconds")),
            version=as_str(meta.get("version")) or as_str(result.metadata.get("version")) or None,
            exit_code=as_int(meta.get("exit_code")),
            raw=result.raw_count,
            findings=len(result.findings),
            suppressed=result.suppressed,
            errors=errors,
        )
    for name, meta in metas.items():
        if name in runs:
            continue
        status = as_str(meta.get("status"), "error")
        errors = []
        report_name = as_str(meta.get("report"))
        if status == "ok" and report_name and not any(reports.rglob(report_name)):
            status, errors = "error", [f"meta says {report_name} was written but it is missing"]
        elif status == "error":
            errors = [as_str(meta.get("reason")) or f"scanner exited with {meta.get('exit_code')}"]
        runs[name] = ToolRun(
            name=name,
            parser=None,
            report=as_str(meta.get("report")) or None,
            status=status,
            duration=as_float(meta.get("duration_seconds")),
            version=as_str(meta.get("version")) or None,
            exit_code=as_int(meta.get("exit_code")),
            errors=errors if status != "skipped" else [as_str(meta.get("reason"), "skipped")],
        )
    return sorted(runs.values(), key=lambda r: (STAGE_ORDER.index(r.stage), r.name)), parsed


def check_expected(expected: list[str], runs: list[ToolRun]) -> list[str]:
    """Fail closed: every expected scanner must have produced a usable report."""
    problems: list[str] = []
    for name in expected:
        matching = [
            r
            for r in runs
            if r.name == name or r.name.startswith(name + "-") or r.parser == name or r.name.startswith(name)
        ]
        if not matching:
            problems.append(f"{name}: expected but no report was produced (scanner missing or crashed)")
            continue
        if all(r.status == "skipped" for r in matching):
            reasons = "; ".join(e for r in matching for e in r.errors)
            problems.append(f"{name}: expected but skipped ({reasons})")
            continue
        for run in matching:
            if run.status == "error":
                problems.append(f"{run.name}: {'; '.join(run.errors)[:300]}")
    return problems


def _stage_summaries(
    result_findings: list[Finding], fixed: list[Finding], runs: list[ToolRun], gate: str
) -> dict[str, StageSummary]:
    stages = {name: StageSummary(name) for name in STAGE_ORDER}
    for run in runs:
        stage = stages[run.stage]
        if run.parser != "pip-licenses" and run.name != "syft":
            stage.tools.append(run.name)
        if run.status == "error":
            stage.result = "error"
    for finding in result_findings:
        stage = stages[finding.stage]
        if finding.status == "existing":
            stage.existing += 1
        else:
            stage.new += 1
        if finding.decision == "block":
            stage.blocking += 1
        elif finding.decision == "warn":
            stage.warnings += 1
    for finding in fixed:
        stages[finding.stage].fixed += 1
    for stage in stages.values():
        if stage.result == "error":
            continue
        if not stage.tools and stage.new == stage.existing == stage.fixed == 0:
            stage.result = "pending" if (stage.name == "DAST" and gate == "gate-1") else "skipped"
        elif stage.blocking:
            stage.result = "fail"
        elif stage.warnings:
            stage.result = "warn"
    return stages


def run_gate(opts: GateOptions) -> GateResult:
    today = opts.today or dt.date.today()
    generated_at = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    warnings: list[str] = []
    tool_errors: list[str] = []

    try:
        policy = Policy.load(opts.policy)
    except PolicyError as exc:
        policy = Policy.from_dict({"defaults": {}})
        tool_errors.append(str(exc))

    runs, parsed = collect(opts.reports) if opts.reports.is_dir() else ([], [])
    if not opts.reports.is_dir():
        tool_errors.append(f"reports directory {opts.reports} does not exist")
    tool_errors.extend(check_expected(opts.expect, runs))
    for result in parsed:
        warnings.extend(result.warnings)

    findings = [f for r in parsed for f in r.findings]
    licences = [lic for r in parsed for lic in r.licences]
    findings.extend(evaluate_licences(licences, policy))

    suppressions: list[Suppression] = scan(opts.source_root) if opts.source_root else []
    findings.extend(unjustified_findings(suppressions))

    raw_results = sum(r.raw_count for r in parsed if r.tool != "pip-licenses") + (
        len(findings) - sum(len(r.findings) for r in parsed)
    )
    unique, stats = deduplicate(findings, raw_results)

    intel = opts.intel or ThreatIntel(opts.cache_dir)
    enrichment = EnrichmentReport(errors=["enrichment disabled (--offline)"]) if opts.offline else intel.enrich(unique)
    warnings.extend(enrichment.errors)

    baseline: Baseline | None
    baseline, baseline_warnings = load_baseline(opts.baseline)
    warnings.extend(baseline_warnings)
    fixed = diff(unique, baseline)
    known = baseline.suppression_keys if baseline else set()
    new_suppressions = sum(1 for s in suppressions if s.key not in known) if baseline else len(suppressions)

    evaluation = evaluate(
        unique,
        policy,
        branch=opts.branch,
        event=opts.event,
        today=today,
        new_suppressions=new_suppressions,
        labels=opts.labels,
        tools_run=frozenset(name for r in runs if r.status != "skipped" for name in (r.name, r.parser) if name),
    )
    warnings.extend(evaluation.warnings)
    for finding in unique:
        finding.first_seen = finding.first_seen or today.isoformat()
        if finding.decision in {"block", "warn"}:
            finding.due_date = due_date(finding, policy, today)

    unique.sort(key=lambda f: (-int(f.severity), STAGE_ORDER.index(f.stage), f.location))
    if tool_errors:
        outcome, code = "error", EXIT_ERROR
    elif not evaluation.passed:
        outcome, code = "block", EXIT_BLOCK
    else:
        outcome, code = "pass", EXIT_PASS
    return GateResult(
        options=opts,
        outcome=outcome,
        exit_code=code,
        findings=unique,
        fixed=fixed,
        runs=runs,
        tool_errors=tool_errors,
        dedupe=stats,
        enrichment=enrichment,
        suppressions=suppressions,
        evaluation=evaluation,
        stages=_stage_summaries(unique, fixed, runs, opts.stage),
        warnings=warnings,
        policy_ref=opts.policy_ref or f"{policy.source}@{policy.digest or 'invalid'}",
        generated_at=generated_at,
        sla_days=dict(policy.sla_days),
    )
