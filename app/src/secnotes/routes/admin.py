"""Admin export: all notes as a gzipped tarball, built in memory with
``tarfile`` so no shell or external process is ever involved."""

from __future__ import annotations

import io
import json
import logging
import tarfile
import time
from typing import Annotated, Any

from fastapi import APIRouter, Body, Request, Response
from sqlalchemy import select

from secnotes.auth import AdminUser, DbSession
from secnotes.models import Note
from secnotes.requestctx import client_ip
from secnotes.schemas import ExportRequest

router = APIRouter(prefix="/admin", tags=["admin"])
security_log = logging.getLogger("secnotes.security")


def _add_json(tar: tarfile.TarFile, name: str, data: dict[str, Any], mtime: int) -> None:
    raw = json.dumps(data, indent=2, default=str).encode("utf-8")
    info = tarfile.TarInfo(name=name)
    info.size = len(raw)
    info.mtime = mtime
    info.mode = 0o644
    info.uname = info.gname = "secnotes"
    tar.addfile(info, io.BytesIO(raw))


@router.post("/export")
def export_notes(
    request: Request,
    admin: AdminUser,
    db: DbSession,
    payload: Annotated[ExportRequest | None, Body()] = None,
) -> Response:
    options = payload or ExportRequest()
    notes = db.scalars(select(Note).order_by(Note.id)).all()
    mtime = int(time.time())
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        _add_json(tar, "manifest.json", {"notes": len(notes), "exported_by": admin.username}, mtime)
        for note in notes:
            _add_json(
                tar,
                f"notes/{note.id}.json",
                {
                    "id": note.id,
                    "owner_id": note.owner_id,
                    "title": note.title,
                    "body": note.body,
                    "created_at": note.created_at,
                    "updated_at": note.updated_at,
                },
                mtime,
            )
    security_log.info(
        "export created",
        extra={
            "event": "export_created",
            "user_id": admin.id,
            "notes": len(notes),
            "client_ip": client_ip(request),
        },
    )
    return Response(
        content=buffer.getvalue(),
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{options.filename}.tar.gz"'},
    )
