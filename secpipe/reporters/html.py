"""Self-contained HTML report (Jinja2, autoescaped) for offline sharing."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from secpipe.aggregator.gate import GateResult
from secpipe.aggregator.models import STAGE_ORDER, Severity

_env = Environment(
    loader=PackageLoader("secpipe.reporters", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(result: GateResult) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(
        r=result,
        summary=result.summary(),
        stages=[result.stages[name] for name in STAGE_ORDER],
        severities=[s.label for s in reversed(Severity)],
        findings=result.findings,
    )
