"""Registration, login, token refresh/rotation, logout and MFA enrolment."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime
from typing import NoReturn

import pyotp
from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select, update

from secnotes.auth import (
    AuthError,
    CurrentUser,
    DbSession,
    TokenClaims,
    burn_hash_time,
    get_tokens,
    hash_password,
    needs_rehash,
    unauthorized,
    verify_password,
)
from secnotes.metrics import LOGIN_ATTEMPTS, REFRESH_TOKEN_REUSE
from secnotes.models import RefreshToken, RevokedAccessToken, User
from secnotes.ratelimit import limiter, login_limit
from secnotes.requestctx import client_ip, set_context
from secnotes.schemas import (
    LoginRequest,
    MfaEnableRequest,
    MfaSetupOut,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserOut,
)

router = APIRouter(tags=["auth"])
security_log = logging.getLogger("secnotes.security")


@router.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(request: Request, payload: RegisterRequest, db: DbSession) -> User:
    username = payload.username.lower()
    if db.scalar(select(User).where(User.username == username)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username already taken")
    # New accounts are always plain users; admins are created with `python -m secnotes.manage`.
    user = User(username=username, password_hash=hash_password(payload.password), role="user")
    db.add(user)
    db.commit()
    db.refresh(user)
    security_log.info(
        "user registered",
        extra={
            "event": "user_registered",
            "user_id": user.id,
            "username": username,
            "client_ip": client_ip(request),
        },
    )
    return user


def _login_failed(
    request: Request, username: str, reason: str, detail: str = "invalid credentials"
) -> NoReturn:
    security_log.warning(
        "login failed",
        extra={
            "event": "login_failed",
            "username": username,
            "reason": reason,
            "client_ip": client_ip(request),
            "user_agent": request.headers.get("user-agent", "")[:200],
        },
    )
    LOGIN_ATTEMPTS.labels("failure").inc()
    raise unauthorized(detail)


def _issue_pair(
    request: Request, db: DbSession, user: User, family_id: str
) -> tuple[TokenPair, TokenClaims, str]:
    tokens = get_tokens(request)
    access, access_claims = tokens.issue_access(user)
    refresh, refresh_claims = tokens.issue_refresh(user, family_id)
    db.add(
        RefreshToken(
            jti=refresh_claims.jti,
            user_id=user.id,
            family_id=family_id,
            expires_at=refresh_claims.expires_at,
        )
    )
    pair = TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=int(tokens.access_ttl.total_seconds()),
    )
    return pair, access_claims, refresh_claims.jti


@router.post("/auth/login", response_model=TokenPair)
@limiter.limit(login_limit)
def login(request: Request, payload: LoginRequest, db: DbSession) -> TokenPair:
    username = payload.username.lower()
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        burn_hash_time(payload.password)
        _login_failed(request, username, "unknown_user")
    if not verify_password(user.password_hash, payload.password):
        _login_failed(request, username, "bad_password")
    if user.mfa_enabled:
        if payload.totp_code is None:
            _login_failed(request, username, "mfa_required", "MFA code required")
        if user.totp_secret is None or not pyotp.TOTP(user.totp_secret).verify(
            payload.totp_code, valid_window=1
        ):
            _login_failed(request, username, "mfa_invalid")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
    pair, access_claims, _ = _issue_pair(request, db, user, secrets.token_hex(16))
    db.commit()
    set_context(request, user_id=user.id, jti=access_claims.jti)
    security_log.info(
        "login succeeded",
        extra={
            "event": "login_success",
            "username": username,
            "user_id": user.id,
            "client_ip": client_ip(request),
            "jti": access_claims.jti,
            "mfa": user.mfa_enabled,
        },
    )
    LOGIN_ATTEMPTS.labels("success").inc()
    return pair


@router.post("/auth/refresh", response_model=TokenPair)
def refresh(request: Request, payload: RefreshRequest, db: DbSession) -> TokenPair:
    try:
        claims = get_tokens(request).decode(payload.refresh_token, "refresh")
    except AuthError as exc:
        raise unauthorized("invalid refresh token") from exc
    record = db.get(RefreshToken, claims.jti)
    if record is None or record.user_id != claims.user_id:
        raise unauthorized("invalid refresh token")
    now = datetime.now(UTC)
    if record.revoked_at is not None:
        # A rotated token came back: assume it was stolen and kill the whole family.
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == record.family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        db.commit()
        security_log.warning(
            "refresh token reuse detected",
            extra={
                "event": "refresh_token_reuse",
                "user_id": record.user_id,
                "family_id": record.family_id,
                "client_ip": client_ip(request),
            },
        )
        REFRESH_TOKEN_REUSE.inc()
        raise unauthorized("invalid refresh token")
    user = db.get(User, claims.user_id)
    if user is None:
        raise unauthorized("invalid refresh token")
    pair, _, new_jti = _issue_pair(request, db, user, record.family_id)
    record.revoked_at = now
    record.replaced_by = new_jti
    db.commit()
    security_log.info(
        "token refreshed",
        extra={"event": "token_refreshed", "user_id": user.id, "client_ip": client_ip(request)},
    )
    return pair


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, payload: RefreshRequest, user: CurrentUser, db: DbSession) -> Response:
    now = datetime.now(UTC)
    try:
        claims = get_tokens(request).decode(payload.refresh_token, "refresh")
    except AuthError:
        claims = None
    if claims is not None and claims.user_id == user.id:
        record = db.get(RefreshToken, claims.jti)
        if record is not None and record.revoked_at is None:
            record.revoked_at = now
    access_claims = request.state.token_claims
    if db.get(RevokedAccessToken, access_claims.jti) is None:
        db.add(RevokedAccessToken(jti=access_claims.jti, expires_at=access_claims.expires_at))
    db.commit()
    security_log.info(
        "logout", extra={"event": "logout", "user_id": user.id, "client_ip": client_ip(request)}
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users/me", response_model=UserOut)
def me(user: CurrentUser) -> User:
    return user


@router.post("/users/me/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(user: CurrentUser, db: DbSession) -> MfaSetupOut:
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA already enabled")
    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="SecNotes")
    return MfaSetupOut(secret=secret, otpauth_uri=uri)


@router.post("/users/me/mfa/enable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_enable(request: Request, payload: MfaEnableRequest, user: CurrentUser, db: DbSession) -> Response:
    if user.totp_secret is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="run MFA setup first")
    if not pyotp.TOTP(user.totp_secret).verify(payload.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid MFA code")
    user.mfa_enabled = True
    db.commit()
    security_log.info(
        "mfa enabled", extra={"event": "mfa_enabled", "user_id": user.id, "client_ip": client_ip(request)}
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
