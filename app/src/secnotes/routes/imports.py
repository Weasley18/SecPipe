"""YAML note import (``POST /notes/import``).

The module is named ``imports`` because ``import`` is a Python keyword.
"""

from __future__ import annotations

import logging
from typing import Annotated

import yaml
from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status
from pydantic import TypeAdapter, ValidationError

from secnotes.auth import CurrentUser, DbSession
from secnotes.config import Settings
from secnotes.models import Note
from secnotes.requestctx import client_ip
from secnotes.schemas import ImportResult, NoteImportItem

router = APIRouter(prefix="/notes", tags=["notes"])
security_log = logging.getLogger("secnotes.security")
_ITEMS: TypeAdapter[list[NoteImportItem]] = TypeAdapter(list[NoteImportItem])


def _reject(request: Request, code: int, reason: str, detail: str) -> HTTPException:
    security_log.info(
        "import rejected",
        extra={"event": "import_rejected", "reason": reason, "client_ip": client_ip(request)},
    )
    return HTTPException(status_code=code, detail=detail)


@router.post("/import", response_model=ImportResult, status_code=status.HTTP_201_CREATED)
def import_notes(
    request: Request, user: CurrentUser, db: DbSession, file: Annotated[UploadFile, File()]
) -> ImportResult:
    settings: Settings = request.app.state.settings
    raw = file.file.read(settings.max_import_bytes + 1)
    if len(raw) > settings.max_import_bytes:
        raise _reject(request, status.HTTP_413_CONTENT_TOO_LARGE, "too_large", "import file too large")
    try:
        # safe_load builds plain data only (dict/list/str/int...), never Python objects.
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise _reject(request, status.HTTP_400_BAD_REQUEST, "invalid_yaml", "invalid YAML") from exc
    if isinstance(document, dict) and set(document) == {"notes"}:
        document = document["notes"]
    if not isinstance(document, list):
        raise _reject(request, status.HTTP_422_UNPROCESSABLE_CONTENT, "not_a_list", "expected a list of notes")
    if len(document) > settings.max_import_notes:
        raise _reject(request, status.HTTP_413_CONTENT_TOO_LARGE, "too_many", "too many notes in one import")
    try:
        items = _ITEMS.validate_python(document)
    except ValidationError as exc:
        errors = [{"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors) from exc
    db.add_all(Note(owner_id=user.id, title=item.title, body=item.body) for item in items)
    db.commit()
    return ImportResult(imported=len(items))
