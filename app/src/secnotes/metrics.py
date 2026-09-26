"""Prometheus metrics, served on a separate internal port.

Keeping ``/metrics`` off the API port means the Ingress can never expose it;
only the monitoring namespace may reach the metrics port (NetworkPolicy
``allow-prometheus-scrape``).
"""

from __future__ import annotations

import threading

from prometheus_client import Counter, Histogram, start_http_server

HTTP_REQUESTS = Counter(
    "secnotes_http_requests_total", "HTTP requests by route and status", ["method", "route", "status"]
)
HTTP_LATENCY = Histogram(
    "secnotes_http_request_duration_seconds", "HTTP request latency", ["method", "route"]
)
LOGIN_ATTEMPTS = Counter("secnotes_login_attempts_total", "Login attempts by outcome", ["outcome"])
PREVIEW_BLOCKED = Counter(
    "secnotes_preview_blocked_total", "Preview URLs rejected by the SSRF guard", ["reason"]
)
REFRESH_TOKEN_REUSE = Counter(
    "secnotes_refresh_token_reuse_total", "Rotated refresh tokens presented again (possible theft)"
)
RATE_LIMITED = Counter("secnotes_rate_limited_total", "Requests rejected by rate limiting", ["route"])

_lock = threading.Lock()
_started = False


def start_metrics_server(port: int) -> bool:
    """Start the metrics HTTP server once per process. Port 0 disables it."""
    global _started  # noqa: PLW0603 -- process-wide singleton guard
    if port <= 0:
        return False
    with _lock:
        if _started:
            return False
        start_http_server(port)
        _started = True
        return True
