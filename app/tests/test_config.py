"""Flaw #1 fix: no secrets in code; config comes from env or mounted files."""

from __future__ import annotations

from pathlib import Path

import pytest

from secnotes.config import ConfigError, Settings

STRONG = "x" * 48


def test_jwt_secret_required() -> None:
    with pytest.raises(ConfigError, match="JWT_SECRET"):
        Settings.from_env({"SECNOTES_ENV": "development"})


def test_weak_jwt_secret_rejected() -> None:
    with pytest.raises(ConfigError, match="256 bits"):
        Settings.from_env({"SECNOTES_ENV": "development", "SECNOTES_JWT_SECRET": "secret123"})


def test_secrets_read_from_files(tmp_path: Path) -> None:
    (tmp_path / "jwt").write_text(STRONG + "\n")
    (tmp_path / "db").write_text("p@ss word")
    settings = Settings.from_env(
        {
            "SECNOTES_JWT_SECRET_FILE": str(tmp_path / "jwt"),
            "SECNOTES_DB_HOST": "postgres",
            "SECNOTES_DB_PASSWORD_FILE": str(tmp_path / "db"),
            "SECNOTES_CORS_ORIGINS": "https://a.example, https://b.example",
            "SECNOTES_PREVIEW_ALLOWED_HOSTS": "Example.com",
            "SECNOTES_METRICS_PORT": "0",
            "SECNOTES_ENABLE_DOCS": "true",
        }
    )
    assert settings.jwt_secret == STRONG
    assert settings.database_url == "postgresql+psycopg://secnotes:p%40ss+word@postgres:5432/secnotes"
    assert settings.cors_origins == ("https://a.example", "https://b.example")
    assert settings.preview_allowed_hosts == ("example.com",)
    assert settings.enable_docs is True
    assert "p@ss" not in repr(settings) and STRONG not in repr(settings)


def test_unreadable_secret_file() -> None:
    with pytest.raises(ConfigError, match="unreadable"):
        Settings.from_env({"SECNOTES_JWT_SECRET_FILE": "/nonexistent/secret"})


def test_production_requires_database() -> None:
    with pytest.raises(ConfigError, match="DATABASE_URL"):
        Settings.from_env({"SECNOTES_JWT_SECRET": STRONG})
    with pytest.raises(ConfigError, match="DB_PASSWORD"):
        Settings.from_env({"SECNOTES_JWT_SECRET": STRONG, "SECNOTES_DB_HOST": "db"})
    assert Settings.from_env(
        {"SECNOTES_JWT_SECRET": STRONG, "SECNOTES_ENV": "development"}
    ).database_url.startswith("sqlite")


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"SECNOTES_CORS_ORIGINS": "*"}, "explicit"),
        ({"SECNOTES_CORS_ORIGINS": "http://evil.example"}, "https"),
        ({"SECNOTES_ACCESS_TOKEN_MINUTES": "600"}, "between 1 and 60"),
        ({"SECNOTES_REFRESH_TOKEN_DAYS": "365"}, "between 1 and 30"),
        ({"SECNOTES_METRICS_PORT": "abc"}, "integer"),
        ({"SECNOTES_ENV": "staging"}, "environment"),
    ],
)
def test_unsafe_settings_rejected(env: dict[str, str], message: str) -> None:
    base = {"SECNOTES_JWT_SECRET": STRONG, "SECNOTES_DATABASE_URL": "sqlite://"}
    with pytest.raises(ConfigError, match=message):
        Settings.from_env({**base, **env})


def test_no_hardcoded_secrets_in_source() -> None:
    src = Path(__file__).resolve().parents[1] / "src" / "secnotes"
    text = "\n".join(p.read_text() for p in src.rglob("*.py"))
    for needle in ("AKIA", "secret123", "supersecret", "BEGIN PRIVATE KEY"):
        assert needle not in text
