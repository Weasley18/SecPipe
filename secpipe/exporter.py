"""Tiny Prometheus exporter for SecPipe's metrics history.

CI appends one JSON line per gate run to ``metrics/history.jsonl`` on the
``secpipe-metrics`` branch (an audit trail in git). This exporter, running in
the local monitoring stack, reloads that file (a path or an https URL) and
serves the latest record per (branch, gate) on ``/metrics``.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from secpipe.aggregator.normalize import as_dict, as_float, as_list, as_str
from secpipe.http import HttpError, check_url
from secpipe.reporters.prometheus import format_samples

Sample = tuple[str, dict[str, str], float]


def parse_history(text: str) -> list[dict[str, Any]]:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(as_dict(json.loads(line)))
        except json.JSONDecodeError:
            continue  # a torn last line must not take the exporter down
    return records


def latest_samples(records: list[dict[str, Any]]) -> list[Sample]:
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        latest[(as_str(record.get("branch")), as_str(record.get("gate")))] = record
    samples: list[Sample] = []
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for (branch, gate), record in sorted(latest.items()):
        for item in as_list(record.get("samples")):
            item = as_dict(item)
            labels = {str(k): str(v) for k, v in as_dict(item.get("labels")).items()}
            labels.setdefault("branch", branch or "unknown")
            labels.setdefault("gate", gate or "gate")
            key = (as_str(item.get("name")), tuple(sorted(labels.items())))
            value = as_float(item.get("value"))
            if value is None or key in seen:
                continue
            seen.add(key)
            samples.append((key[0], labels, value))
    return samples


def backfill(history: str) -> str:
    """OpenMetrics with timestamps for ``promtool tsdb create-blocks-from openmetrics``."""
    out: list[str] = []
    declared: set[str] = set()
    for record in parse_history(history):
        stamp = dt.datetime.fromisoformat(as_str(record.get("timestamp"))).timestamp()
        for item in as_list(record.get("samples")):
            item = as_dict(item)
            name = as_str(item.get("name"))
            labels = {str(k): str(v) for k, v in as_dict(item.get("labels")).items()}
            labels.setdefault("branch", as_str(record.get("branch"), "unknown"))
            labels.setdefault("gate", as_str(record.get("gate"), "gate"))
            value = as_float(item.get("value"))
            if value is None:
                continue
            if name not in declared:
                out.append(f"# TYPE {name} gauge")
                declared.add(name)
            text = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
            out.append(f"{name}{{{text}}} {value:g} {stamp:.3f}")
    out.append("# EOF")
    return "\n".join(out) + "\n"


class HistorySource:
    def __init__(self, location: str, refresh: int = 300) -> None:
        self.location = location
        self.refresh = refresh
        self._samples: list[Sample] = []
        self._loaded = 0.0
        self._lock = threading.Lock()
        self.last_error: str | None = None

    def _read(self) -> str:
        if self.location.startswith(("http://", "https://")):
            check_url(self.location)
            with urllib.request.urlopen(self.location, timeout=20) as resp:  # noqa: S310  # nosec B310 -- scheme validated by check_url()
                return str(resp.read().decode("utf-8"))
        return Path(self.location).read_text(encoding="utf-8")

    def samples(self) -> list[Sample]:
        with self._lock:
            if time.time() - self._loaded >= self.refresh or not self._loaded:
                try:
                    self._samples = latest_samples(parse_history(self._read()))
                    self.last_error = None
                except (OSError, HttpError, ValueError) as exc:
                    self.last_error = str(exc)  # keep serving the last good data
                self._loaded = time.time()
            return list(self._samples)


def make_handler(source: HistorySource) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.rstrip("/") not in {"/metrics", ""}:
                self.send_error(404)
                return
            body = format_samples(source.samples())
            up = 0 if source.last_error else 1
            body += f"# TYPE secpipe_exporter_up gauge\nsecpipe_exporter_up {up}\n"
            payload = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def serve(location: str, port: int = 9108, refresh: int = 300) -> None:  # pragma: no cover - blocking loop
    source = HistorySource(location, refresh)
    # Binds all interfaces inside its pod; NetworkPolicy limits who can reach it.
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(source))  # noqa: S104  # nosec B104 -- pod-local bind
    server.serve_forever()
