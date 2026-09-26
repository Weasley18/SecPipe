"""Runtime configuration.

Secrets are read from files first (``<NAME>_FILE`` pointing at a mounted
Kubernetes Secret or Docker secret) and only then from plain environment
variables. Nothing secret has a default: the app refuses to start without
a strong JWT key instead of silently falling back to a weak one.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote_plus

PREFIX = "SECNOTES_"
MIN_JWT_SECRET_BYTES = 32  # 256-bit HMAC-SHA256 key
ENVIRONMENTS = ("production", "development", "test")


class ConfigError(RuntimeError):
    """Raised when configuration is missing or unsafe."""


def _read_secret(name: str, env: Mapping[str, str]) -> str | None:
    file_var = f"{PREFIX}{name}_FILE"
    path = env.get(file_var)
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"{file_var} points at an unreadable file") from exc
    value = env.get(f"{PREFIX}{name}")
    return value.strip() if value else None


def _csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(f"{PREFIX}{name}")
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{PREFIX}{name} must be an integer") from exc


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(f"{PREFIX}{name}")
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _database_url(env: Mapping[str, str], environment: str) -> str:
    url = _read_secret("DATABASE_URL", env)
    if url:
        return url
    host = env.get(f"{PREFIX}DB_HOST")
    if host:
        password = _read_secret("DB_PASSWORD", env)
        if not password:
            raise ConfigError(f"{PREFIX}DB_PASSWORD (or {PREFIX}DB_PASSWORD_FILE) is required")
        user = env.get(f"{PREFIX}DB_USER", "secnotes")
        name = env.get(f"{PREFIX}DB_NAME", "secnotes")
        port = env.get(f"{PREFIX}DB_PORT", "5432")
        return f"postgresql+psycopg://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{name}"
    if environment == "production":
        raise ConfigError(f"{PREFIX}DATABASE_URL or {PREFIX}DB_HOST must be set in production")
    return "sqlite:///./secnotes.db"


@dataclass(frozen=True)
class Settings:
    """Validated settings. Construct with :meth:`from_env` in real deployments."""

    database_url: str = field(repr=False)
    jwt_secret: str = field(repr=False)
    jwt_audience: str = "secnotes-api"
    jwt_issuer: str = "secnotes"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    cors_origins: tuple[str, ...] = ()
    preview_allowed_hosts: tuple[str, ...] = ()
    login_rate_limit: str = "5/minute"
    default_rate_limit: str = "120/minute"
    rate_limit_storage_uri: str = "memory://"
    max_import_bytes: int = 256 * 1024
    max_import_notes: int = 500
    max_request_bytes: int = 1024 * 1024
    metrics_port: int = 9090
    enable_docs: bool = False
    require_admin_mfa: bool = False
    log_level: str = "INFO"
    environment: str = "production"

    def __post_init__(self) -> None:
        if len(self.jwt_secret.encode("utf-8")) < MIN_JWT_SECRET_BYTES:
            raise ConfigError(
                f"JWT secret must be at least {MIN_JWT_SECRET_BYTES} bytes (256 bits); "
                "generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )
        if "*" in self.cors_origins:
            raise ConfigError("CORS origins must be explicit; '*' is not allowed with credentials")
        for origin in self.cors_origins:
            if not origin.startswith(("https://", "http://localhost", "http://127.0.0.1")):
                raise ConfigError(f"CORS origin {origin!r} must use https (or be localhost)")
        if not 1 <= self.access_token_minutes <= 60:
            raise ConfigError("access token lifetime must be between 1 and 60 minutes")
        if not 1 <= self.refresh_token_days <= 30:
            raise ConfigError("refresh token lifetime must be between 1 and 30 days")
        if self.environment not in ENVIRONMENTS:
            raise ConfigError(f"environment must be one of {ENVIRONMENTS}")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        environment = env.get(f"{PREFIX}ENV", "production").strip().lower()
        secret = _read_secret("JWT_SECRET", env)
        if not secret:
            raise ConfigError(f"{PREFIX}JWT_SECRET (or {PREFIX}JWT_SECRET_FILE) is required")
        return cls(
            database_url=_database_url(env, environment),
            jwt_secret=secret,
            jwt_audience=env.get(f"{PREFIX}JWT_AUDIENCE", "secnotes-api"),
            jwt_issuer=env.get(f"{PREFIX}JWT_ISSUER", "secnotes"),
            access_token_minutes=_int(env, "ACCESS_TOKEN_MINUTES", 15),
            refresh_token_days=_int(env, "REFRESH_TOKEN_DAYS", 7),
            cors_origins=_csv(env.get(f"{PREFIX}CORS_ORIGINS")),
            preview_allowed_hosts=tuple(h.lower() for h in _csv(env.get(f"{PREFIX}PREVIEW_ALLOWED_HOSTS"))),
            login_rate_limit=env.get(f"{PREFIX}LOGIN_RATE_LIMIT", "5/minute"),
            default_rate_limit=env.get(f"{PREFIX}DEFAULT_RATE_LIMIT", "120/minute"),
            rate_limit_storage_uri=env.get(f"{PREFIX}RATE_LIMIT_STORAGE_URI", "memory://"),
            max_import_bytes=_int(env, "MAX_IMPORT_BYTES", 256 * 1024),
            max_import_notes=_int(env, "MAX_IMPORT_NOTES", 500),
            max_request_bytes=_int(env, "MAX_REQUEST_BYTES", 1024 * 1024),
            metrics_port=_int(env, "METRICS_PORT", 9090),
            enable_docs=_bool(env, "ENABLE_DOCS", False),
            require_admin_mfa=_bool(env, "REQUIRE_ADMIN_MFA", False),
            log_level=env.get(f"{PREFIX}LOG_LEVEL", "INFO").upper(),
            environment=environment,
        )
