"""Loki (query_range) and Alertmanager (v2 alerts) clients."""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlencode

from secpipe.aggregator.normalize import as_dict, as_list, as_str
from secpipe.correlator.events import LogEvent, from_line
from secpipe.correlator.rules import Alert
from secpipe.http import request_json

Requester = Callable[..., Any]
RUNBOOK_BASE = "https://github.com/Weasley18/SecPipe/blob/main/docs/runbooks/"


class LokiClient:
    def __init__(self, url: str, request: Requester = request_json, tenant: str | None = None) -> None:
        self.url = url.rstrip("/")
        self._request = request
        self._headers = {"X-Scope-OrgID": tenant} if tenant else {}

    def query_range(self, query: str, start: dt.datetime, end: dt.datetime, limit: int = 5000) -> list[LogEvent]:
        params = urlencode(
            {
                "query": query,
                "start": str(int(start.timestamp() * 1e9)),
                "end": str(int(end.timestamp() * 1e9)),
                "limit": str(limit),
                "direction": "forward",
            }
        )
        data = as_dict(self._request("GET", f"{self.url}/loki/api/v1/query_range?{params}", headers=self._headers))
        events: list[LogEvent] = []
        for stream in as_list(as_dict(data.get("data")).get("result")):
            stream = as_dict(stream)
            labels = {str(k): str(v) for k, v in as_dict(stream.get("stream")).items()}
            for value in as_list(stream.get("values")):
                if isinstance(value, list) and len(value) >= 2:
                    event = from_line(as_str(value[1]), labels, as_str(value[0]))
                    if event is not None:
                        events.append(event)
        return events


def explore_url(grafana: str, ip: str | None, pod: str | None) -> str:
    selector = '{namespace=~"secnotes|ingress-nginx"}'
    needle = ip or pod or ""
    expr = f'{selector} |= "{needle}"' if needle else selector
    state = {
        "datasource": "loki",
        "queries": [{"refId": "A", "expr": expr}],
        "range": {"from": "now-1h", "to": "now"},
    }
    return f"{grafana.rstrip('/')}/explore?left={quote(json.dumps(state, separators=(',', ':')))}"


def to_alertmanager(alert: Alert, now: dt.datetime, grafana: str, runbook_base: str = RUNBOOK_BASE) -> dict[str, Any]:
    labels = {
        "alertname": "SecNotes" + "".join(part.title() for part in alert.rule.split("_")),
        "severity": alert.severity,
        "rule": alert.rule,
        "service": "secnotes",
        "source": "secpipe-correlator",
        **alert.labels,
    }
    return {
        "labels": labels,
        "annotations": {
            "summary": alert.summary,
            "description": alert.description,
            "runbook_url": runbook_base + alert.runbook,
            "grafana_explore_url": explore_url(grafana, alert.labels.get("source_ip"), alert.labels.get("pod")),
            "evidence_count": str(alert.evidence),
            "first_seen": alert.first_seen.isoformat() if alert.first_seen else "",
        },
        "startsAt": (alert.first_seen or now).isoformat(),
        # Re-sent every minute while the evidence is in the window; resolves ~10 min after it ages out.
        "endsAt": (now + dt.timedelta(minutes=10)).isoformat(),
        "generatorURL": explore_url(grafana, alert.labels.get("source_ip"), alert.labels.get("pod")),
    }


class AlertmanagerClient:
    def __init__(self, url: str, request: Requester = request_json) -> None:
        self.url = url.rstrip("/")
        self._request = request

    def send(self, alerts: list[dict[str, Any]]) -> None:
        if alerts:
            self._request("POST", f"{self.url}/api/v2/alerts", body=alerts)
