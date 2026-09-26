"""Outputs: every audience gets its own view of the same normalised findings.

* ``findings.json`` / ``gate.json``  next run's baseline, machine consumers
* ``comment.md`` / ``summary.md``    sticky PR comment and job summary
* ``secpipe.sarif``                  GitHub code scanning (Security tab)
* ``report.html``                    offline sharing (Jinja2)
* ``metrics.prom`` / ``metrics.json`` Prometheus exposition + history record
"""

from __future__ import annotations

from pathlib import Path

from secpipe.aggregator.gate import GateResult
from secpipe.reporters import html, jsonout, markdown, prometheus, sarif


def write_outputs(result: GateResult, out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    stage = result.options.stage
    return [
        jsonout.write(out / "findings.json", jsonout.findings_document(result)),
        jsonout.write(out / f"{stage}.json", result.summary()),
        _text(out / "comment.md", markdown.render_comment(result)),
        _text(out / "summary.md", markdown.render_summary(result)),
        jsonout.write(out / "secpipe.sarif", sarif.render(result)),
        _text(out / "report.html", html.render(result)),
        _text(out / "metrics.prom", prometheus.render(result)),
        jsonout.write(out / "metrics.json", prometheus.history_record(result)),
    ]


def _text(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path
