"""Admin export of all notes as a tarball."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from fastapi import APIRouter, Body
from fastapi.responses import FileResponse
from sqlalchemy import select

from secnotes.auth import AdminUser, DbSession
from secnotes.models import Note

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/export")
def export_notes(admin: AdminUser, db: DbSession, payload: dict[str, Any] = Body(default={})) -> FileResponse:
    filename = payload.get("filename", "notes-export")
    workdir = f"/tmp/export-{admin.id}"
    os.makedirs(workdir, exist_ok=True)
    for note in db.scalars(select(Note)).all():
        with open(os.path.join(workdir, f"{note.id}.json"), "w") as fh:
            json.dump({"id": note.id, "owner_id": note.owner_id, "title": note.title, "body": note.body}, fh)
    # PLANTED FLAW #7: shell command built from user input (command injection).
    subprocess.run(f"tar czf /tmp/{filename}.tar.gz -C {workdir} .", shell=True, check=True)
    return FileResponse(f"/tmp/{filename}.tar.gz", filename=f"{filename}.tar.gz")
