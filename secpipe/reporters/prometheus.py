"""Prometheus exposition for one gate run, plus a JSON history record.

A GitHub-hosted runner cannot reach a Prometheus on a laptop, so CI appends
``history_record()`` to ``metrics/history.jsonl`` on the ``secpipe-metrics``
branch; ``secpipe exporter`` (monitoring/exporter) serves the latest values
per branch and ``secpipe metrics backfill`` turns the history into OpenMetrics
for ``promtool tsdb create-blocks-from openmetrics``.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from typing import Any

from secpipe.aggregator.gate import GateResult
from secpipe.aggregator.models import Severity

HELP: dict[str, tuple[str, str]] = {
    "secpipe_findings": ("gauge", "Findings in the latest run by severity, category and status"),
    "secpipe_gate_result": ("gauge", "1 if the gate passed, 0 if it blocked or failed closed"),
    "secpipe_scan_duration_seconds": ("gauge", "Scanner wall-clock duration in the latest run"),
    "secpipe_findings_raw": ("gauge", "Raw scanner results before deduplication"),
    "secpipe_findings_unique": ("gauge", "Unique findings after deduplication"),
    "secpipe_findings_deduplicated_total": ("gauge", "Results removed by deduplication in the latest run"),
    "secpipe_findings_blocking": ("gauge", "Findings that block the gate"),
    "secpipe_exceptions_active": ("gauge", "Active policy exceptions"),
    "secpipe_exception_expiry_days": ("gauge", "Days until each active exception expires"),
    "secpipe_package_findings": ("gauge", "Findings per vulnerable package (top 20)"),
    "secpipe_sla_days": ("gauge", "Remediation SLA from policy.yaml"),
    "secpipe_suppressions": ("gauge", "In-code scanner suppressions"),
    "secpipe_last_run_timestamp_seconds": ("gauge", "Unix time of the latest gate run"),
}


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def samples(result: GateResult) -> list[tuple[str, dict[str, str], float]]:
    opts = result.options
    branch = opts.branch or "unknown"
    gate = opts.stage
    out: list[tuple[str, dict[str, str], float]] = []
    counts: Counter[tuple[str, str, str]] = Counter()
    for finding in [*result.findings, *result.fixed]:
        counts[(finding.severity.label, finding.category, finding.status)] += 1
    for (severity, category, status), n in sorted(counts.items()):
        out.append(
            (
                "secpipe_findings",
                {"severity": severity, "category": category, "status": status, "branch": branch},
                n,
            )
        )
    out.append(("secpipe_gate_result", {"gate": gate, "branch": branch}, 1.0 if result.outcome == "pass" else 0.0))
    for run in result.runs:
        if run.duration is not None:
            out.append(("secpipe_scan_duration_seconds", {"tool": run.name}, run.duration))
    out.append(("secpipe_findings_raw", {"branch": branch}, result.dedupe.raw))
    out.append(("secpipe_findings_unique", {"branch": branch}, result.dedupe.unique))
    out.append(("secpipe_findings_deduplicated_total", {}, result.dedupe.removed))
    for sev in reversed(Severity):
        out.append(
            (
                "secpipe_findings_blocking",
                {"severity": sev.label, "branch": branch},
                sum(1 for f in result.blocking if f.severity == sev),
            )
        )
    today = opts.today or dt.date.today()
    expiring = {e.label for e in result.evaluation.expiring_exceptions}
    active = result.evaluation.active_exceptions
    out.append(
        (
            "secpipe_exceptions_active",
            {"expiring_soon": "true"},
            sum(1 for e in active if e.label in expiring),
        )
    )
    out.append(
        (
            "secpipe_exceptions_active",
            {"expiring_soon": "false"},
            sum(1 for e in active if e.label not in expiring),
        )
    )
    for exc in active:
        out.append(
            (
                "secpipe_exception_expiry_days",
                {"exception": exc.label, "owner": exc.owner},
                (exc.expires - today).days,
            )
        )
    packages: Counter[str] = Counter(
        f.package for f in result.findings if f.package and f.decision in {"block", "warn"}
    )
    for package, n in packages.most_common(20):
        out.append(("secpipe_package_findings", {"package": package, "branch": branch}, n))
    for label, days in sorted(result.sla_days.items()):
        out.append(("secpipe_sla_days", {"severity": label}, days))
    out.append(("secpipe_suppressions", {"justified": "true"}, sum(1 for s in result.suppressions if s.justified)))
    out.append(
        (
            "secpipe_suppressions",
            {"justified": "false"},
            sum(1 for s in result.suppressions if not s.justified),
        )
    )
    stamp = dt.datetime.fromisoformat(result.generated_at).timestamp()
    out.append(("secpipe_last_run_timestamp_seconds", {"gate": gate, "branch": branch}, stamp))
    return out


def format_samples(items: list[tuple[str, dict[str, str], float]], timestamp_ms: int | None = None) -> str:
    lines: list[str] = []
    declared: set[str] = set()
    for name, labels, value in items:
        if name not in declared:
            kind, text = HELP.get(name, ("gauge", name))
            lines += [f"# HELP {name} {text}", f"# TYPE {name} {kind}"]
            declared.add(name)
        label_text = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
        suffix = f" {timestamp_ms}" if timestamp_ms is not None else ""
        lines.append(
            f"{name}{{{label_text}}} {float(value):g}{suffix}" if label_text else f"{name} {float(value):g}{suffix}"
        )
    return "\n".join(lines) + "\n"


def render(result: GateResult) -> str:
    return format_samples(samples(result))


def history_record(result: GateResult) -> dict[str, Any]:
    opts = result.options
    return {
        "timestamp": result.generated_at,
        "branch": opts.branch,
        "gate": opts.stage,
        "event": opts.event,
        "commit": opts.commit,
        "outcome": result.outcome,
        "samples": [{"name": n, "labels": labels, "value": v} for n, labels, v in samples(result)],
    }
