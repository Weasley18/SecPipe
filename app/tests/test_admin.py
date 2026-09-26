"""Admin export: flaw #7 (command injection) regression tests."""

from __future__ import annotations

import io
import json
import tarfile

from fastapi.testclient import TestClient

from conftest import make_admin, make_settings, make_user


def test_non_admin_forbidden(client: TestClient) -> None:
    headers = make_user(client, "alice")
    assert client.post("/admin/export", headers=headers).status_code == 403
    assert client.post("/admin/export").status_code == 401


def test_admin_export_is_a_valid_tarball(client: TestClient) -> None:
    alice = make_user(client, "alice")
    client.post("/notes", json={"title": "a1", "body": "hello"}, headers=alice)
    admin = make_admin(client)
    response = client.post("/admin/export", json={"filename": "backup_2026"}, headers=admin)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/gzip"
    assert response.headers["content-disposition"] == 'attachment; filename="backup_2026.tar.gz"'
    with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
        names = tar.getnames()
        assert names == ["manifest.json", "notes/1.json"]
        manifest = tar.extractfile("manifest.json")
        assert manifest is not None
        assert json.load(manifest) == {"notes": 1, "exported_by": "admin"}
    default = client.post("/admin/export", headers=admin)
    assert 'filename="notes-export.tar.gz"' in default.headers["content-disposition"]


def test_export_filename_injection_rejected(client: TestClient) -> None:
    admin = make_admin(client)
    for name in ("x; rm -rf /", "$(id)", "../../etc/passwd", "a`whoami`", "x" * 65):
        response = client.post("/admin/export", json={"filename": name}, headers=admin)
        assert response.status_code == 422, name


def test_admin_mfa_can_be_required() -> None:
    from secnotes.main import create_app

    with TestClient(create_app(make_settings(require_admin_mfa=True))) as strict:
        admin = make_admin(strict)
        response = strict.post("/admin/export", headers=admin)
        assert response.status_code == 403
        assert response.json()["detail"] == "MFA enrollment required"
