"""Generate monitoring/grafana/dashboards/secpipe-security-posture.json.

Kept as code so the panels stay reviewable in diffs; run it after editing:
    python monitoring/grafana/build_dashboard.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}
MAIN = 'branch="main"'
SEVERITY_COLOURS = {
    "critical": "dark-red",
    "high": "red",
    "medium": "orange",
    "low": "yellow",
    "info": "blue",
}


def target(
    expr: str, legend: str = "", *, instant: bool = False, ref: str = "A", ds: dict[str, str] = PROM
) -> dict[str, Any]:
    t: dict[str, Any] = {"datasource": ds, "expr": expr, "refId": ref, "legendFormat": legend}
    if instant:
        t.update(instant=True, range=False, format="table")
    return t


def severity_overrides() -> list[dict[str, Any]]:
    return [
        {
            "matcher": {"id": "byName", "options": sev},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": colour}}],
        }
        for sev, colour in SEVERITY_COLOURS.items()
    ]


def panel(
    pid: int, title: str, kind: str, grid: tuple[int, int, int, int], targets: list[dict[str, Any]], **extra: Any
) -> dict[str, Any]:
    x, y, w, h = grid
    p: dict[str, Any] = {
        "id": pid,
        "title": title,
        "type": kind,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": targets[0]["datasource"],
        "targets": targets,
        "fieldConfig": {"defaults": {}, "overrides": []},
        "options": {},
    }
    for key, value in extra.items():
        if key == "defaults":
            p["fieldConfig"]["defaults"].update(value)
        elif key == "overrides":
            p["fieldConfig"]["overrides"] = value
        else:
            p[key] = value
    return p


def build() -> dict[str, Any]:
    open_findings = f'sum by (severity) (secpipe_findings{{{MAIN}, status!="fixed"}})'
    panels = [
        # Build-time risk ------------------------------------------------------
        panel(
            1,
            "1. Open findings by severity (main)",
            "stat",
            (0, 0, 12, 5),
            [target(open_findings, "{{severity}}")],
            description="Latest gate-2 run on main; fixed findings excluded.",
            options={
                "colorMode": "background",
                "textMode": "value_and_name",
                "graphMode": "none",
                "reduceOptions": {"calcs": ["lastNotNull"]},
            },
            defaults={"color": {"mode": "fixed", "fixedColor": "green"}, "noValue": "0"},
            overrides=severity_overrides(),
        ),
        panel(
            2,
            "Gate result (latest)",
            "stat",
            (12, 0, 4, 5),
            [target(f'min(secpipe_gate_result{{{MAIN}, gate="gate-2"}})')],
            options={"colorMode": "background", "reduceOptions": {"calcs": ["lastNotNull"]}},
            defaults={
                "mappings": [
                    {
                        "type": "value",
                        "options": {"0": {"text": "BLOCKED", "color": "red"}, "1": {"text": "PASS", "color": "green"}},
                    }
                ]
            },
        ),
        panel(
            3,
            "Noise removed by dedupe",
            "stat",
            (16, 0, 8, 5),
            [
                target(f"max(secpipe_findings_raw{{{MAIN}}})", "raw results", ref="A"),
                target(f"max(secpipe_findings_unique{{{MAIN}}})", "unique findings", ref="B"),
            ],
            options={"textMode": "value_and_name", "graphMode": "none", "reduceOptions": {"calcs": ["lastNotNull"]}},
        ),
        panel(
            4,
            "2. Findings trend, 30 days, by category",
            "timeseries",
            (0, 5, 12, 8),
            [target(f'sum by (category) (secpipe_findings{{{MAIN}, status!="fixed"}})', "{{category}}")],
            timeFrom="30d",
            defaults={"custom": {"stacking": {"mode": "normal"}, "fillOpacity": 40, "drawStyle": "line"}},
        ),
        panel(
            5,
            "3. Gate pass rate per week (main)",
            "timeseries",
            (12, 5, 12, 8),
            [target(f'avg_over_time(secpipe_gate_result{{{MAIN}, gate="gate-2"}}[1w])', "pass rate")],
            timeFrom="90d",
            interval="1d",
            defaults={"unit": "percentunit", "min": 0, "max": 1, "custom": {"drawStyle": "bars", "fillOpacity": 60}},
        ),
        panel(
            6,
            "4. Top 10 vulnerable packages",
            "bargauge",
            (0, 13, 8, 9),
            [target(f"topk(10, max by (package) (secpipe_package_findings{{{MAIN}}}))", "{{package}}", instant=True)],
            options={
                "orientation": "horizontal",
                "displayMode": "gradient",
                "reduceOptions": {"calcs": ["lastNotNull"]},
            },
        ),
        panel(
            7,
            "5. Mean time to remediate vs SLA (days)",
            "table",
            (8, 13, 8, 9),
            [
                target("max by (severity) (secpipe_mttr_days)", instant=True, ref="MTTR"),
                target("max by (severity) (secpipe_sla_days)", instant=True, ref="SLA"),
                target("max by (severity) (secpipe_open_issues)", instant=True, ref="Open"),
                target("max by (severity) (secpipe_issue_age_days)", instant=True, ref="Age"),
            ],
            transformations=[
                {"id": "merge", "options": {}},
                {
                    "id": "organize",
                    "options": {
                        "excludeByName": {"Time": True},
                        "renameByName": {
                            "Value #MTTR": "MTTR (days)",
                            "Value #SLA": "SLA (days)",
                            "Value #Open": "Open issues",
                            "Value #Age": "Mean age (days)",
                        },
                    },
                },
            ],
            defaults={"decimals": 1},
        ),
        panel(
            8,
            "6. Exceptions expiring in the next 14 days",
            "table",
            (16, 13, 8, 9),
            [target("secpipe_exception_expiry_days < 14", instant=True)],
            transformations=[
                {
                    "id": "organize",
                    "options": {
                        "excludeByName": {"Time": True, "__name__": True, "instance": True, "job": True},
                        "renameByName": {"Value": "days left"},
                    },
                }
            ],
            defaults={
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "red", "value": None},
                        {"color": "orange", "value": 3},
                        {"color": "green", "value": 7},
                    ],
                },
                "custom": {"cellOptions": {"type": "color-background"}},
            },
        ),
        panel(
            9,
            "7. Scan duration per tool (latest run)",
            "bargauge",
            (0, 22, 12, 9),
            [target("max by (tool) (secpipe_scan_duration_seconds)", "{{tool}}", instant=True)],
            options={"orientation": "horizontal", "displayMode": "basic", "reduceOptions": {"calcs": ["lastNotNull"]}},
            defaults={"unit": "s"},
        ),
        # Run-time risk --------------------------------------------------------
        panel(
            10,
            "8. Runtime alerts from Falco",
            "timeseries",
            (12, 22, 12, 9),
            [
                target(
                    'sum by (rule) (count_over_time({namespace="monitoring", app="falco"} |= "output_fields" | json '
                    '| priority=~"Warning|Error|Critical|Alert|Emergency" [5m]))',
                    "{{rule}}",
                    ds=LOKI,
                )
            ],
            description=(
                "Falco events (WARNING and above) shipped by Alloy; "
                "the same events reach Alertmanager via Falcosidekick."
            ),
            defaults={"custom": {"drawStyle": "bars", "fillOpacity": 70, "stacking": {"mode": "normal"}}},
        ),
        panel(
            11,
            "Security alerts firing (correlator + Prometheus rules)",
            "table",
            (0, 31, 12, 8),
            [target('sum by (alertname, severity, rule) (ALERTS{alertstate="firing", team="security"})', instant=True)],
            transformations=[{"id": "organize", "options": {"excludeByName": {"Time": True, "Value": True}}}],
        ),
        panel(
            12,
            "SecNotes security signals",
            "timeseries",
            (12, 31, 12, 8),
            [
                target("sum by (outcome) (rate(secnotes_login_attempts_total[5m]))", "login {{outcome}}", ref="A"),
                target(
                    "sum by (reason) (rate(secnotes_preview_blocked_total[5m]))", "SSRF blocked: {{reason}}", ref="B"
                ),
                target("sum(rate(secnotes_refresh_token_reuse_total[5m]))", "refresh token reuse", ref="C"),
            ],
            defaults={"unit": "reqps"},
        ),
        panel(
            13,
            "Latest SecNotes auth events (Loki)",
            "logs",
            (0, 39, 24, 8),
            [
                target(
                    '{namespace="secnotes", app="secnotes-api"} |= "event" | json '
                    '| event=~"login_.*|token_.*|preview_blocked|authz_denied|rate_limited"',
                    ds=LOKI,
                )
            ],
            options={"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending"},
        ),
    ]
    return {
        "uid": "secpipe-posture",
        "title": "SecPipe Security Posture",
        "description": "Build-time risk from the SecPipe gate next to run-time detection: one pane of glass.",
        "tags": ["secpipe", "security"],
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "editable": True,
        "refresh": "1m",
        "time": {"from": "now-24h", "to": "now"},
        "templating": {"list": []},
        "annotations": {"list": []},
        "links": [
            {
                "title": "Runbooks",
                "type": "link",
                "url": "https://github.com/Weasley18/SecPipe/tree/main/docs/runbooks",
                "targetBlank": True,
            }
        ],
        "panels": panels,
    }


if __name__ == "__main__":
    out = Path(__file__).parent / "dashboards" / "secpipe-security-posture.json"
    out.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
