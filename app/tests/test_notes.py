"""Notes: flaw #2 (SQL injection) and flaw #3 (IDOR) regression tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import ORMExecuteState, Session

from conftest import make_user


def test_note_crud(client: TestClient) -> None:
    headers = make_user(client, "alice")
    created = client.post("/notes", json={"title": "Groceries", "body": "milk"}, headers=headers)
    assert created.status_code == 201
    note_id = created.json()["id"]
    assert client.get(f"/notes/{note_id}", headers=headers).json()["body"] == "milk"
    updated = client.put(f"/notes/{note_id}", json={"body": "oat milk"}, headers=headers)
    assert updated.json() == {**updated.json(), "title": "Groceries", "body": "oat milk"}
    assert [n["id"] for n in client.get("/notes", headers=headers).json()] == [note_id]
    assert client.delete(f"/notes/{note_id}", headers=headers).status_code == 204
    assert client.get(f"/notes/{note_id}", headers=headers).status_code == 404


def test_note_validation(client: TestClient) -> None:
    headers = make_user(client, "val")
    assert client.post("/notes", json={"title": ""}, headers=headers).status_code == 422
    assert client.post("/notes", json={"title": "x", "owner_id": 1}, headers=headers).status_code == 422
    assert client.get("/notes?limit=1000", headers=headers).status_code == 422
    # One past PostgreSQL INTEGER: the database raised "integer out of range" (500).
    too_big = 2**31
    assert client.get(f"/notes/{too_big}", headers=headers).status_code == 422
    assert client.put(f"/notes/{too_big}", json={"title": "x"}, headers=headers).status_code == 422
    assert client.delete(f"/notes/{too_big}", headers=headers).status_code == 422
    assert client.get("/notes/0", headers=headers).status_code == 422


def test_nul_bytes_are_rejected(client: TestClient) -> None:
    # PostgreSQL text cannot hold NUL (psycopg raises, the app answered 500; found
    # by ZAP's API scan on main). SQLite stores it, so assert the 422 directly.
    headers = make_user(client, "nul")
    note_id = client.post("/notes", json={"title": "ok"}, headers=headers).json()["id"]
    assert client.post("/notes", json={"title": "a\x00b"}, headers=headers).status_code == 422
    assert client.post("/notes", json={"title": "ok", "body": "x\x00"}, headers=headers).status_code == 422
    assert client.put(f"/notes/{note_id}", json={"body": "x\x00"}, headers=headers).status_code == 422
    assert client.get("/notes/search", params={"q": "\x00"}, headers=headers).status_code == 422
    upload = {"file": ("notes.yaml", b'- title: "a\\0b"\n', "application/x-yaml")}
    assert client.post("/notes/import", files=upload, headers=headers).status_code == 422
    assert client.post("/auth/login", json={"username": "a\x00", "password": "x" * 12}).status_code == 422
    assert client.get(f"/notes/{note_id}", headers=headers).json()["title"] == "ok"


def test_update_and_delete_lock_the_note_row(client: TestClient) -> None:
    # A DELETE racing a PUT of the same note made the PUT reload a deleted row:
    # a 500 on PostgreSQL (ZAP's multi-threaded API scan on main). PUT and DELETE
    # read the note with SELECT ... FOR UPDATE so they serialise; SQLite has no
    # row locks, so check the statements as PostgreSQL would receive them.
    headers = make_user(client, "lock")
    note_id = client.post("/notes", json={"title": "x"}, headers=headers).json()["id"]
    note_reads: list[str] = []

    def record(state: ORMExecuteState) -> None:
        sql = str(state.statement.compile(dialect=postgresql.dialect()))
        if state.is_select and "FROM notes" in sql:
            note_reads.append(sql)

    def reads_during(method: str) -> tuple[int, list[str]]:
        note_reads.clear()
        response = client.request(
            method, f"/notes/{note_id}", json={"body": "y"} if method == "PUT" else None, headers=headers
        )
        return response.status_code, list(note_reads)

    event.listen(Session, "do_orm_execute", record)
    try:
        status, reads = reads_during("GET")
        assert status == 200 and reads and not any("FOR UPDATE" in sql for sql in reads)
        for method, expected in (("PUT", 200), ("DELETE", 204)):
            status, reads = reads_during(method)
            assert status == expected and "FOR UPDATE" in reads[0], method
    finally:
        event.remove(Session, "do_orm_execute", record)


def test_user_b_gets_404_on_user_a_note(client: TestClient) -> None:
    alice = make_user(client, "alice")
    bob = make_user(client, "bob")
    note_id = client.post("/notes", json={"title": "secret plan"}, headers=alice).json()["id"]

    assert client.get(f"/notes/{note_id}", headers=bob).status_code == 404
    assert client.put(f"/notes/{note_id}", json={"title": "pwned"}, headers=bob).status_code == 404
    assert client.delete(f"/notes/{note_id}", headers=bob).status_code == 404
    # A missing id and someone else's id are indistinguishable.
    assert client.get("/notes/999999", headers=bob).json() == client.get(f"/notes/{note_id}", headers=bob).json()
    assert client.get(f"/notes/{note_id}", headers=alice).json()["title"] == "secret plan"
    assert client.get("/notes", headers=bob).json() == []


def test_search_is_scoped_and_parameterised(client: TestClient) -> None:
    alice = make_user(client, "alice")
    bob = make_user(client, "bob")
    client.post("/notes", json={"title": "alice diary", "body": "top secret"}, headers=alice)
    client.post("/notes", json={"title": "bob diary", "body": "100% sure_thing"}, headers=bob)

    assert [n["title"] for n in client.get("/notes/search", params={"q": "diary"}, headers=bob).json()] == ["bob diary"]
    for payload in ("' OR '1'='1", "%' OR 1=1 --", "x' UNION SELECT id, title, body, 1, 1 FROM notes --"):
        response = client.get("/notes/search", params={"q": payload}, headers=bob)
        assert response.status_code == 200
        assert response.json() == []
    # LIKE wildcards in the term are literal, not patterns.
    assert len(client.get("/notes/search", params={"q": "100%"}, headers=bob).json()) == 1
    assert client.get("/notes/search", params={"q": "%"}, headers=alice).json() == []
    assert client.get("/notes/search", params={"q": "_"}, headers=bob).json()[0]["title"] == "bob diary"
    assert client.get("/notes/search", params={"q": ""}, headers=bob).status_code == 422
