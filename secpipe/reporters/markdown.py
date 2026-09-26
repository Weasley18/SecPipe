"""Sticky PR comment and job summary.

Short by design: blocking findings in full, everything else collapsed. A
comment developers skim beats one they ignore. GitHub caps comments at 65,536
characters, so long tables are truncated with a pointer to the artifacts.
"""

from __future__ import annotations

from urllib.parse import quote

from secpipe.aggregator.gate import GateResult
from secpipe.aggregator.models import STAGE_ORDER, Finding, Severity

MARKER = "<!-- secpipe:sticky -->"
MAX_ROWS = 40
MAX_CHARS = 60_000
RESULT_ICON = {
    "pass": "pass",  # nosec B105 -- gate result label shown in the PR comment, not a credential
    "warn": "warn",
    "fail": "**fail**",
    "error": "**error**",
    "pending": "pending",
    "skipped": "skipped",
}


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _headline(result: GateResult) -> str:
    if result.outcome == "error":
        return f"## SecPipe: ERROR (failed closed: {len(result.tool_errors)} scanner/config problem(s))"
    blocking = result.blocking
    if result.outcome == "block":
        counts = [
            f"{sum(1 for f in blocking if f.severity == s)} {s.label}"
            for s in reversed(Severity)
            if any(f.severity == s for f in blocking)
        ]
        all_new = blocking and all(f.status == "new" for f in blocking)
        detail = ", ".join(counts) + (" new" if all_new else "")
        if not blocking:
            detail = f"{len(result.evaluation.gate_errors)} policy violation(s)"
        return f"## SecPipe: BLOCKED ({detail})"
    return f"## SecPipe: PASSED (0 blocking, {len(result.warned)} warnings)"


def _link(result: GateResult, finding: Finding) -> str:
    opts = result.options
    location = _cell(finding.location)
    if finding.file and opts.repository and opts.commit and not finding.file.startswith("image:"):
        anchor = f"#L{finding.line}" if finding.line else ""
        url = f"https://github.com/{opts.repository}/blob/{opts.commit}/{quote(finding.file)}{anchor}"
        return f"[{location}]({url})"
    return f"`{location}`"


def _fix(finding: Finding) -> str:
    if finding.category == "secret":
        return "Rotate + remove"
    if finding.fix_available is False:
        return "no fix yet"
    if finding.fix_version:
        return _cell(f">= {finding.fix_version}" if finding.package else finding.fix_version)
    if finding.help_url:
        return f"[guide]({finding.help_url})"
    return "-"


def _badges(finding: Finding) -> str:
    badges = []
    if finding.in_kev:
        badges.append("KEV")
    if finding.epss is not None and finding.epss >= 0.01:
        badges.append(f"EPSS {finding.epss:.2f}")
    if finding.also_reported_by:
        badges.append("+" + ",".join(finding.also_reported_by))
    return f" <sub>{' '.join(badges)}</sub>" if badges else ""


def _os_summary_row(findings: list[Finding]) -> str:
    worst = max(f.severity for f in findings)
    by_sev = ", ".join(
        f"{sum(1 for f in findings if f.severity == s)} {s.label}"
        for s in reversed(Severity)
        if any(f.severity == s for f in findings)
    )
    fixable = sum(1 for f in findings if f.fix_available)
    packages = len({f.package for f in findings})
    return (
        f"| {worst.name} | trivy | {len(findings)} OS package CVEs across {packages} packages ({by_sev}); "
        f"{fixable} have a fix | base image OS | rebuild on a patched, supported base |"
    )


def _table(result: GateResult, findings: list[Finding], limit: int = MAX_ROWS) -> list[str]:
    """Findings ordered by stage then severity. OS-package CVEs are one summary
    row: they share one fix (a new base image) and would drown everything else."""
    os_packages = [f for f in findings if f.pkg_type == "os"]
    rows = [f for f in findings if f.pkg_type != "os"] if len(os_packages) > 3 else list(findings)
    rows.sort(key=lambda f: (STAGE_ORDER.index(f.stage), -int(f.severity), f.location))
    lines = ["| Sev | Tool | Finding | Location | Fix |", "|---|---|---|---|---|"]
    for f in rows[:limit]:
        title = _cell(f.title) + (f" ({_cell(f.cve)})" if f.cve and f.cve not in f.title else "")
        lines.append(f"| {f.severity.name} | {f.tool} | {title}{_badges(f)} | {_link(result, f)} | {_fix(f)} |")
    if len(os_packages) > 3:
        lines.append(_os_summary_row(os_packages))
    if len(rows) > limit:
        lines.append(f"\n_...and {len(rows) - limit} more: see `findings.json` or the HTML report artifact._")
    return lines


def _stage_table(result: GateResult) -> list[str]:
    lines = ["| Stage | Result | New | Existing | Fixed |", "|---|---|---|---|---|"]
    for name in STAGE_ORDER:
        stage = result.stages[name]
        if stage.result in {"pending", "skipped"}:
            lines.append(f"| {name} | {stage.result} | - | - | - |")
        else:
            lines.append(f"| {name} | {RESULT_ICON[stage.result]} | {stage.new} | {stage.existing} | {stage.fixed} |")
    return lines


def _tools_table(result: GateResult) -> list[str]:
    lines = ["| Scanner | Stage | Status | Raw | Duration | Version |", "|---|---|---|---|---|---|"]
    for run in result.runs:
        duration = f"{run.duration:.1f}s" if run.duration is not None else "-"
        lines.append(
            f"| {run.name} | {run.stage} | {run.status} | {run.raw} | {duration} | {_cell(run.version or '-')} |"
        )
    return lines


def _body(result: GateResult, collapse: bool) -> list[str]:
    opts = result.options
    context = [opts.stage]
    if opts.branch:
        context.append(f"branch policy `{opts.branch}`")
    if opts.commit:
        context.append(f"commit `{opts.commit[:7]}`")
    if opts.run_url:
        context.append(f"[workflow run]({opts.run_url})")
    lines = [_headline(result), f"<sub>{' · '.join(context)}</sub>", ""]

    if result.tool_errors:
        lines += [
            "### Failed closed",
            "A scanner that should have run produced no usable report, so the gate cannot pass:",
            "",
        ]
        lines += [f"- {_cell(e)}" for e in result.tool_errors] + [""]
    if result.evaluation.gate_errors:
        lines += ["### Policy violations", ""] + [f"- {_cell(e)}" for e in result.evaluation.gate_errors] + [""]

    lines += [*_stage_table(result), ""]

    if result.blocking:
        lines += ["### Blocking findings", *_table(result, result.blocking, limit=80), ""]
    warned = result.warned
    if warned:
        lines += _details(f"Warnings ({len(warned)})", _table(result, warned), collapse)
    if result.excepted:
        rows = [
            f"- `{f.fingerprint}` {_cell(f.title)} at `{_cell(f.location)}`: "
            f"{_cell(f.reasons[-1] if f.reasons else '')}"
            for f in result.excepted[:MAX_ROWS]
        ]
        lines += _details(f"Accepted exceptions ({len(result.excepted)})", rows, collapse)
    if result.fixed:
        rows = [f"- {_cell(f.title)} at `{_cell(f.location)}` ({f.tool})" for f in result.fixed[:MAX_ROWS]]
        lines += _details(f"Fixed since base branch ({len(result.fixed)})", rows, collapse)
    stats = result.dedupe
    lines += _details(
        f"Scanners ({len(result.runs)}) · {stats.raw} raw results -> {stats.unique} unique findings",
        _tools_table(result),
        collapse,
    )
    if result.warnings:
        lines += _details(
            f"Notes ({len(result.warnings)})", [f"- {_cell(w)}" for w in result.warnings[:MAX_ROWS]], collapse
        )

    s = result.evaluation
    lines.append(
        f"Suppressions this PR: {s.new_suppressions} of {s.rules.max_suppressions_per_pr} allowed. "
        f"Policy: `{result.policy_ref}` (block at >= {s.rules.block_at_or_above.label})."
    )
    return lines


def _details(summary: str, rows: list[str], collapse: bool) -> list[str]:
    if not collapse:
        return [f"### {summary}", *rows, ""]
    return [f"<details><summary>{summary}</summary>", "", *rows, "", "</details>", ""]


def _fit(text: str) -> str:
    if len(text) <= MAX_CHARS:
        return text
    return text[: MAX_CHARS - 200] + "\n\n_Comment truncated: see the HTML report artifact for everything._\n"


def render_comment(result: GateResult) -> str:
    return _fit("\n".join([MARKER, *_body(result, collapse=True)]) + "\n")


def render_summary(result: GateResult) -> str:
    return _fit("\n".join(_body(result, collapse=False)) + "\n")
