from __future__ import annotations

import io
from pathlib import Path

import pytest

from secnotes import manage


def test_create_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SECNOTES_ENV", "development")
    monkeypatch.setenv("SECNOTES_JWT_SECRET", "y" * 48)
    monkeypatch.setenv("SECNOTES_DATABASE_URL", f"sqlite:///{tmp_path / 'm.db'}")
    assert manage.main(["init-db"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("a strong admin password\n"))
    assert manage.main(["create-user", "--username", "Root", "--role", "admin", "--password-stdin"]) == 0
    assert "created admin root" in capsys.readouterr().out
    monkeypatch.setattr("sys.stdin", io.StringIO("a strong admin password\n"))
    assert manage.main(["create-user", "--username", "root", "--password-stdin"]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert manage.main(["create-user", "--username", "other", "--password-stdin"]) == 2


def test_lazy_app_attribute(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import logging

    import secnotes.main as main_module

    monkeypatch.setenv("SECNOTES_ENV", "development")
    monkeypatch.setenv("SECNOTES_JWT_SECRET", "z" * 48)
    monkeypatch.setenv("SECNOTES_DATABASE_URL", f"sqlite:///{tmp_path / 'lazy.db'}")
    monkeypatch.setenv("SECNOTES_METRICS_PORT", "0")
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    monkeypatch.setattr(main_module, "_app", None)
    try:
        app = main_module.app
        assert app is main_module.app
        assert app.title == "SecNotes API"
        with pytest.raises(AttributeError):
            main_module.nope  # noqa: B018
    finally:
        root.handlers[:], level = saved
        root.setLevel(level)
