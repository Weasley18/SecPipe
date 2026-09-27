"""Request and response models.

Every request model forbids unknown fields, so mass-assignment style attacks
(for example sending ``"role": "admin"`` at registration) fail validation.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

USERNAME_PATTERN = r"^[A-Za-z0-9_.-]{3,32}$"
# PostgreSQL text cannot hold NUL: psycopg raises and the request ended in a 500
# (ZAP's API scan on main). Every free-text input that reaches the database
# rejects it with a 422 instead.
NO_NUL = r"^[^\x00]*$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(StrictModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64, pattern=NO_NUL)
    password: str = Field(min_length=1, max_length=128)
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class RefreshRequest(StrictModel):
    refresh_token: str = Field(min_length=20, max_length=4096)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 -- OAuth token type name, not a credential
    expires_in: int


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    mfa_enabled: bool


class NoteCreate(StrictModel):
    title: str = Field(min_length=1, max_length=200, pattern=NO_NUL)
    body: str = Field(default="", max_length=10_000, pattern=NO_NUL)


class NoteUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200, pattern=NO_NUL)
    body: str | None = Field(default=None, max_length=10_000, pattern=NO_NUL)


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    body: str
    created_at: datetime
    updated_at: datetime


class NoteImportItem(StrictModel):
    title: str = Field(min_length=1, max_length=200, pattern=NO_NUL)
    body: str = Field(default="", max_length=10_000, pattern=NO_NUL)


class ImportResult(BaseModel):
    imported: int


class PreviewOut(BaseModel):
    url: str
    title: str | None
    description: str | None


class ExportRequest(StrictModel):
    filename: str = Field(default="notes-export", pattern=r"^[A-Za-z0-9_-]{1,64}$")


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaEnableRequest(StrictModel):
    code: str = Field(pattern=r"^\d{6}$")
