"""Authentication fixes: flaws #4 (JWT), #8 (password hashing), #11 (logging + rate limit)."""

from __future__ import annotations

import base64
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta

import jwt
import pyotp
import pytest
from fastapi.testclient import TestClient

from conftest import PASSWORD, auth_headers, login, make_settings, register
from secnotes.auth import hash_password, verify_password
from secnotes.config import Settings
from secnotes.models import User


def _b64(data: dict[str, object]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _claims(user_id: int, **overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": "secnotes",
        "aud": "secnotes-api",
        "sub": str(user_id),
        "role": "admin",
        "jti": secrets.token_hex(16),
        "typ": "access",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    claims.update(overrides)
    return claims


def test_register_login_and_me(client: TestClient) -> None:
    user = register(client, "alice")
    assert user == {"id": user["id"], "username": "alice", "role": "user", "mfa_enabled": False}
    tokens = login(client, "alice")
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] == 15 * 60
    me = client.get("/users/me", headers=auth_headers(tokens))
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_register_rejects_role_field(client: TestClient) -> None:
    response = client.post(
        "/auth/register", json={"username": "mallory", "password": PASSWORD, "role": "admin"}
    )
    assert response.status_code == 422
    assert PASSWORD not in response.text, "validation errors must not echo submitted values"


def test_register_duplicate_and_weak_password(client: TestClient) -> None:
    register(client, "bob")
    assert client.post("/auth/register", json={"username": "BOB", "password": PASSWORD}).status_code == 409
    assert client.post("/auth/register", json={"username": "carol", "password": "short"}).status_code == 422


def test_passwords_hashed_with_argon2id(client: TestClient) -> None:
    register(client, "dave")
    with client.app.state.db.sessionmaker() as db:  # type: ignore[attr-defined]
        stored = db.query(User).filter_by(username="dave").one().password_hash
    assert stored.startswith("$argon2id$")
    assert verify_password(stored, PASSWORD)
    assert not verify_password(stored, "wrong password!!")
    assert not verify_password("not-a-hash", PASSWORD)
    assert hash_password(PASSWORD) != hash_password(PASSWORD)  # salted


def test_login_failures_are_generic_and_logged(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    register(client, "erin")
    caplog.set_level(logging.WARNING, logger="secnotes.security")
    bad_password = client.post("/auth/login", json={"username": "erin", "password": "wrong password!!"})
    unknown_user = client.post("/auth/login", json={"username": "nobody", "password": "wrong password!!"})
    assert bad_password.status_code == unknown_user.status_code == 401
    assert bad_password.json() == unknown_user.json() == {"detail": "invalid credentials"}
    events = [(r.__dict__.get("event"), r.__dict__.get("reason")) for r in caplog.records]
    assert ("login_failed", "bad_password") in events
    assert ("login_failed", "unknown_user") in events
    failed = next(r for r in caplog.records if r.__dict__.get("event") == "login_failed")
    assert failed.__dict__["client_ip"] == "testclient"


def test_login_rate_limited(client: TestClient) -> None:
    register(client, "frank")
    statuses = [
        client.post("/auth/login", json={"username": "frank", "password": "wrong password!!"}).status_code
        for _ in range(6)
    ]
    assert statuses[:5] == [401] * 5
    assert statuses[5] == 429
    blocked = client.post("/auth/login", json={"username": "frank", "password": PASSWORD})
    assert blocked.status_code == 429, "correct password must not bypass the limit"
    assert blocked.headers["retry-after"] == "60"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda c, s: jwt.encode(c, "secret123", algorithm="HS256"), id="weak-secret"),
        pytest.param(lambda c, s: f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(c)}.", id="alg-none"),
        pytest.param(lambda c, s: jwt.encode(c, s, algorithm="HS512"), id="alg-switch-hs512"),
        pytest.param(
            lambda c, s: jwt.encode({**c, "aud": "other-api"}, s, algorithm="HS256"), id="wrong-aud"
        ),
        pytest.param(lambda c, s: jwt.encode({**c, "iss": "evil"}, s, algorithm="HS256"), id="wrong-iss"),
        pytest.param(
            lambda c, s: jwt.encode(
                {**c, "exp": int(datetime.now(UTC).timestamp()) - 60}, s, algorithm="HS256"
            ),
            id="expired",
        ),
        pytest.param(
            lambda c, s: jwt.encode({k: v for k, v in c.items() if k != "exp"}, s, algorithm="HS256"),
            id="missing-exp",
        ),
        pytest.param(
            lambda c, s: jwt.encode({**c, "typ": "refresh"}, s, algorithm="HS256"), id="refresh-as-access"
        ),
    ],
)
def test_forged_tokens_rejected(client: TestClient, settings: Settings, mutate: object) -> None:
    user = register(client, "grace")
    token = mutate(_claims(user["id"]), settings.jwt_secret)  # type: ignore[operator]
    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_valid_hand_signed_token_accepted(client: TestClient, settings: Settings) -> None:
    user = register(client, "heidi")
    token = jwt.encode(_claims(user["id"], role="user"), settings.jwt_secret, algorithm="HS256")
    assert client.get("/users/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_missing_and_malformed_bearer(client: TestClient) -> None:
    assert client.get("/notes").status_code == 401
    assert client.get("/notes", headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401


def test_refresh_rotation_and_reuse_detection(client: TestClient) -> None:
    register(client, "ivan")
    first = login(client, "ivan")
    rotated = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert rotated.status_code == 200
    second = rotated.json()
    assert second["refresh_token"] != first["refresh_token"]
    # Re-using the rotated token is treated as theft: it fails and kills the family.
    assert client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": second["refresh_token"]}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": second["access_token"]}).status_code == 401


def test_logout_revokes_tokens(client: TestClient) -> None:
    register(client, "judy")
    tokens = login(client, "judy")
    headers = auth_headers(tokens)
    response = client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]}, headers=headers)
    assert response.status_code == 204
    assert client.get("/users/me", headers=headers).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_mfa_enrolment_and_login(client: TestClient) -> None:
    register(client, "ken")
    headers = auth_headers(login(client, "ken"))
    setup = client.post("/users/me/mfa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/SecNotes:ken")
    assert client.post("/users/me/mfa/enable", json={"code": "000000"}, headers=headers).status_code in (
        400,
        204,
    )
    totp = pyotp.TOTP(secret)
    client.post("/users/me/mfa/enable", json={"code": totp.now()}, headers=headers)
    assert client.post("/users/me/mfa/setup", headers=headers).status_code == 409
    missing = client.post("/auth/login", json={"username": "ken", "password": PASSWORD})
    assert missing.status_code == 401
    assert missing.json()["detail"] == "MFA code required"
    ok = client.post("/auth/login", json={"username": "ken", "password": PASSWORD, "totp_code": totp.now()})
    assert ok.status_code == 200


def test_mfa_enable_requires_setup(client: TestClient) -> None:
    register(client, "liam")
    headers = auth_headers(login(client, "liam"))
    assert client.post("/users/me/mfa/enable", json={"code": "123456"}, headers=headers).status_code == 409


def test_token_service_rejects_non_numeric_subject() -> None:
    from secnotes.auth import AuthError, TokenService

    settings = make_settings()
    service = TokenService(settings)
    token = jwt.encode(_claims(1, sub="abc"), settings.jwt_secret, algorithm="HS256")
    with pytest.raises(AuthError):
        service.decode(token, "access")
