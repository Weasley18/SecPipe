"""Password hashing, JWT issue/verify and FastAPI auth dependencies."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Annotated, Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from secnotes.config import Settings
from secnotes.db import get_db
from secnotes.models import RevokedAccessToken, User
from secnotes.requestctx import client_ip, set_context

security_log = logging.getLogger("secnotes.security")

# argon2id with the argon2-cffi defaults (RFC 9106 "low memory" profile).
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash(secrets.token_urlsafe(16))


def burn_hash_time(password: str) -> None:
    """Spend the same time as a real verification so unknown usernames are not
    distinguishable by response time."""
    verify_password(_dummy_hash(), password)


class AuthError(Exception):
    """A token failed validation."""


@dataclass(frozen=True)
class TokenClaims:
    user_id: int
    role: str
    jti: str
    token_type: str
    expires_at: datetime
    family_id: str | None = None


class TokenService:
    """Issues and verifies HS256 JWTs.

    The accepted algorithm list is pinned: the ``alg`` header of an incoming
    token is never trusted, which defeats ``alg: none`` and key-confusion
    tricks. ``exp``, ``aud`` and ``iss`` are always required and checked.
    """

    algorithm = "HS256"

    def __init__(self, settings: Settings) -> None:
        self._secret = settings.jwt_secret
        self._audience = settings.jwt_audience
        self._issuer = settings.jwt_issuer
        self.access_ttl = timedelta(minutes=settings.access_token_minutes)
        self.refresh_ttl = timedelta(days=settings.refresh_token_days)

    def _encode(
        self, user: User, token_type: str, ttl: timedelta, family_id: str | None = None
    ) -> tuple[str, TokenClaims]:
        now = datetime.now(UTC)
        jti = secrets.token_hex(16)
        payload: dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(user.id),
            "role": user.role,
            "jti": jti,
            "typ": token_type,
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
        }
        if family_id:
            payload["fam"] = family_id
        token = jwt.encode(payload, self._secret, algorithm=self.algorithm)
        return token, TokenClaims(user.id, user.role, jti, token_type, now + ttl, family_id)

    def issue_access(self, user: User) -> tuple[str, TokenClaims]:
        return self._encode(user, "access", self.access_ttl)

    def issue_refresh(self, user: User, family_id: str) -> tuple[str, TokenClaims]:
        return self._encode(user, "refresh", self.refresh_ttl, family_id)

    def decode(self, token: str, expected_type: str) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self.algorithm],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "nbf", "sub", "jti", "aud", "iss", "typ"]},
                leeway=5,
            )
        except jwt.PyJWTError as exc:
            raise AuthError(type(exc).__name__) from exc
        if payload.get("typ") != expected_type:
            raise AuthError("WrongTokenType")
        try:
            user_id = int(payload["sub"])
        except (TypeError, ValueError) as exc:
            raise AuthError("InvalidSubject") from exc
        expires_at = datetime.fromtimestamp(int(payload["exp"]), UTC)
        family = payload.get("fam")
        return TokenClaims(
            user_id=user_id,
            role=str(payload.get("role", "")),
            jti=str(payload["jti"]),
            token_type=expected_type,
            expires_at=expires_at,
            family_id=str(family) if family else None,
        )


def get_tokens(request: Request) -> TokenService:
    service: TokenService = request.app.state.tokens
    return service


def unauthorized(detail: str = "not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None:
        raise unauthorized()
    try:
        claims = get_tokens(request).decode(credentials.credentials, "access")
    except AuthError as exc:
        security_log.info(
            "rejected access token",
            extra={"event": "token_rejected", "reason": str(exc), "client_ip": client_ip(request)},
        )
        raise unauthorized("invalid token") from exc
    if db.get(RevokedAccessToken, claims.jti) is not None:
        raise unauthorized("token revoked")
    user = db.get(User, claims.user_id)
    if user is None:
        raise unauthorized("invalid token")
    set_context(request, user_id=user.id, jti=claims.jti)
    request.state.token_claims = claims
    return user


def require_admin(request: Request, user: Annotated[User, Depends(get_current_user)]) -> User:
    if user.role != "admin":
        security_log.warning(
            "admin endpoint denied",
            extra={
                "event": "authz_denied",
                "user_id": user.id,
                "path": request.url.path,
                "client_ip": client_ip(request),
            },
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    settings: Settings = request.app.state.settings
    if settings.require_admin_mfa and not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA enrollment required")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_admin)]
DbSession = Annotated[Session, Depends(get_db)]
