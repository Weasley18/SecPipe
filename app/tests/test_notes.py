"""Notes: flaw #2 (SQL injection) and flaw #3 (IDOR) regression tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

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
