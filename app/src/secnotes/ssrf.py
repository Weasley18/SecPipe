"""SSRF-safe link preview fetching.

Defences, in order:

1. Only ``http``/``https`` on ports 80/443, no credentials in the URL.
2. The host must be on an explicit allow-list (exact name or ``*.domain``).
3. Every address the host resolves to must be a public unicast address, so
   loopback, RFC 1918, link-local (169.254.169.254 cloud metadata), CGNAT and
   reserved ranges are refused, including IPv4-mapped IPv6 forms.
4. Redirects are never followed automatically; each hop is re-validated.
5. Responses are size-capped and time-boxed.

Residual risk: DNS can change between validation and connect (rebinding) for
an allow-listed host. The allow-list, the Kubernetes egress NetworkPolicy and
the Falco egress rule are the defence-in-depth layers for that case.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

MAX_URL_LENGTH = 2048
MAX_BODY_BYTES = 512 * 1024
MAX_REDIRECTS = 3
ALLOWED_PORTS = (80, 443)
TIMEOUT = httpx.Timeout(3.0, connect=2.0)

Resolver = Callable[[str, int], list[str]]


class PreviewBlocked(Exception):
    """The URL is not allowed; ``reason`` is a short machine-readable code."""

    def __init__(self, reason: str, host: str | None = None, address: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.host = host
        self.address = address


class PreviewUnavailable(Exception):
    """The URL was allowed but could not be fetched."""


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def classify_address(address: str) -> str:
    """Return ``public`` or the name of the blocked range the address is in."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return "reserved"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    if ip.is_multicast or ip.is_reserved or not ip.is_global:
        return "reserved"
    return "public"


def host_allowed(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    for entry in allowed_hosts:
        if entry.startswith("*."):
            if host.endswith(entry[1:]):
                return True
        elif host == entry:
            return True
    return False


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    host: str
    port: int
    addresses: tuple[str, ...]


def validate_url(url: str, allowed_hosts: tuple[str, ...], resolver: Resolver) -> ValidatedTarget:
    if len(url) > MAX_URL_LENGTH:
        raise PreviewBlocked("too_long")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise PreviewBlocked("scheme")
    if parts.username is not None or parts.password is not None:
        raise PreviewBlocked("userinfo")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise PreviewBlocked("no_host")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise PreviewBlocked("bad_port", host) from exc
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False
    if is_literal:
        kind = classify_address(host)
        if kind != "public":
            raise PreviewBlocked(kind, host, host)
    if port not in ALLOWED_PORTS:
        raise PreviewBlocked("port", host)
    if not host_allowed(host, allowed_hosts):
        raise PreviewBlocked("not_allowed", host)
    try:
        addresses = resolver(host, port)
    except (OSError, UnicodeError) as exc:
        raise PreviewBlocked("unresolvable", host) from exc
    if not addresses:
        raise PreviewBlocked("unresolvable", host)
    for address in addresses:
        kind = classify_address(address)
        if kind != "public":
            raise PreviewBlocked(kind, host, address)
    return ValidatedTarget(parts.geturl(), host, port, tuple(addresses))


class _MetaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self.description: str | None = None
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title" and self.title is None:
            self._in_title = True
        elif tag == "meta" and self.description is None:
            values = {key.lower(): (value or "") for key, value in attrs}
            name = values.get("name", values.get("property", "")).lower()
            if name in {"description", "og:description"}:
                self.description = values.get("content", "").strip()[:300] or None

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._in_title:
            self._in_title = False
            self.title = "".join(self._title_parts).strip()[:200] or None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


class PreviewFetcher:
    def __init__(
        self,
        allowed_hosts: tuple[str, ...],
        resolver: Resolver = system_resolver,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.allowed_hosts = allowed_hosts
        self._resolver = resolver
        self._transport = transport

    def fetch(self, url: str) -> tuple[str, str | None, str | None]:
        """Return ``(final_url, title, description)`` for an allowed URL."""
        current = url
        with httpx.Client(
            transport=self._transport,
            follow_redirects=False,
            timeout=TIMEOUT,
            headers={"User-Agent": "SecNotes-LinkPreview/1.0"},
        ) as client:
            for _ in range(MAX_REDIRECTS + 1):
                target = validate_url(current, self.allowed_hosts, self._resolver)
                try:
                    with client.stream("GET", target.url) as response:
                        if response.is_redirect:
                            location = response.headers.get("location")
                            if not location:
                                raise PreviewUnavailable("redirect without location")
                            current = urljoin(target.url, location)
                            continue
                        if response.status_code != 200:
                            raise PreviewUnavailable(f"upstream status {response.status_code}")
                        if "text/html" not in response.headers.get("content-type", ""):
                            return target.url, None, None
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            body.extend(chunk)
                            if len(body) >= MAX_BODY_BYTES:
                                break
                        text = bytes(body[:MAX_BODY_BYTES]).decode(
                            response.encoding or "utf-8", errors="replace"
                        )
                except httpx.HTTPError as exc:
                    raise PreviewUnavailable(type(exc).__name__) from exc
                parser = _MetaParser()
                parser.feed(text)
                return target.url, parser.title, parser.description
        raise PreviewBlocked("too_many_redirects")
