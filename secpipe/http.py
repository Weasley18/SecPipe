"""Minimal JSON-over-HTTPS client (standard library only).

Only ``https://`` URLs are allowed (``http://`` only for localhost), so a
misconfigured endpoint can never turn this into a ``file://`` reader.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

USER_AGENT = "secpipe/1.0 (+https://github.com/Weasley18/SecPipe)"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class HttpError(Exception):
    def __init__(self, message: str, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOCAL_HOSTS):
        return
    if parts.scheme == "http" and parts.hostname and parts.hostname.endswith((".svc", ".svc.cluster.local")):
        return  # in-cluster services (Loki, Alertmanager) are plain HTTP behind NetworkPolicy
    raise HttpError(f"refusing non-HTTPS URL: {parts.scheme}://{parts.hostname}")


def request_json(
    method: str,
    url: str,
    *,
    body: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> Any:
    check_url(url)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 -- scheme checked above
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310 -- scheme validated by check_url()
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise HttpError(f"{method} {urlsplit(url).path} -> HTTP {exc.code}", exc.code, detail) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HttpError(f"{method} {urlsplit(url).netloc}: {exc}") from exc
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HttpError(f"{method} {urlsplit(url).path}: invalid JSON response") from exc


def get_json(url: str) -> Any:
    return request_json("GET", url)
