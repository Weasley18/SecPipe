"""Import: flaw #5 (unsafe YAML deserialisation) regression tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import make_settings, make_user


def _upload(client: TestClient, headers: dict[str, str], content: bytes) -> object:
    return client.post("/notes/import", files={"file": ("notes.yaml", content, "application/x-yaml")}, headers=headers)


def test_import_valid_yaml(client: TestClient) -> None:
    headers = make_user(client, "alice")
    response = _upload(client, headers, b"- title: one\n  body: first\n- title: two\n")
    assert response.status_code == 201  # type: ignore[attr-defined]
    assert response.json() == {"imported": 2}  # type: ignore[attr-defined]
    wrapped = _upload(client, headers, b"notes:\n  - title: three\n")
    assert wrapped.json() == {"imported": 1}  # type: ignore[attr-defined]
    assert len(client.get("/notes", headers=headers).json()) == 3


def test_import_rejects_python_object_tags(client: TestClient, tmp_path: object) -> None:
    headers = make_user(client, "bob")
    payloads = [
        b"- !!python/object/apply:os.system ['touch /tmp/pwned']\n",
        b"!!python/object/new:subprocess.check_output [['id']]\n",
        b"- title: !!python/name:os.system\n",
    ]
    for payload in payloads:
        response = _upload(client, headers, payload)
        assert response.status_code == 400, payload  # type: ignore[attr-defined]
    assert client.get("/notes", headers=headers).json() == []


def test_import_schema_and_size_limits(client: TestClient) -> None:
    headers = make_user(client, "carol")
    assert _upload(client, headers, b"just a string").status_code == 422  # type: ignore[attr-defined]
    extra = _upload(client, headers, b"- title: x\n  owner_id: 1\n")
    assert extra.status_code == 422  # type: ignore[attr-defined]
    assert _upload(client, headers, b"- title: [unclosed").status_code == 400  # type: ignore[attr-defined]
    too_big = b"- title: x\n  body: " + b"a" * (256 * 1024) + b"\n"
    assert _upload(client, headers, too_big).status_code == 413  # type: ignore[attr-defined]


def test_import_note_count_limit() -> None:
    from fastapi.testclient import TestClient as TC

    from secnotes.main import create_app

    with TC(create_app(make_settings(max_import_notes=2))) as small:
        headers = make_user(small, "dave")
        response = _upload(small, headers, b"- title: a\n- title: b\n- title: c\n")
        assert response.status_code == 413  # type: ignore[attr-defined]
