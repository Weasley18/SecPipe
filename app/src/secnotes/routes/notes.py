"""Notes CRUD and search. Every query is scoped to the caller's own notes."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Response, status
from sqlalchemy import or_, select

from secnotes.auth import CurrentUser, DbSession
from secnotes.models import Note, User
from secnotes.schemas import NO_NUL, NoteCreate, NoteOut, NoteUpdate

router = APIRouter(prefix="/notes", tags=["notes"])

# Note ids are PostgreSQL INTEGER. A larger id used to reach the database and fail
# there ("integer out of range", an HTTP 500 found by ZAP's API scan on main), so
# it is rejected here like any other invalid input.
NoteId = Annotated[int, Path(ge=1, le=2**31 - 1)]
SearchTerm = Annotated[str, Query(min_length=1, max_length=100, pattern=NO_NUL)]


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _owned_note(db: DbSession, note_id: int, user: User, *, lock: bool = False) -> Note:
    stmt = select(Note).where(Note.id == note_id, Note.owner_id == user.id)
    if lock:
        # SELECT ... FOR UPDATE: a concurrent PUT and DELETE of one note serialise
        # instead of the PUT reloading a row that was deleted under it (a 500 that
        # ZAP's multi-threaded active scan hit on main). SQLite has no row locks.
        stmt = stmt.with_for_update()
    note = db.scalar(stmt)
    if note is None:
        # 404 rather than 403, so callers cannot probe which ids exist.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="note not found")
    return note


@router.get("", response_model=list[NoteOut])
def list_notes(
    user: CurrentUser,
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10_000),
) -> Sequence[Note]:
    stmt = select(Note).where(Note.owner_id == user.id).order_by(Note.id).limit(limit).offset(offset)
    return db.scalars(stmt).all()


@router.post("", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def create_note(payload: NoteCreate, user: CurrentUser, db: DbSession) -> Note:
    note = Note(owner_id=user.id, title=payload.title, body=payload.body)
    db.add(note)
    db.flush()
    db.refresh(note)
    db.commit()
    return note


@router.get("/search", response_model=list[NoteOut])
def search_notes(user: CurrentUser, db: DbSession, q: SearchTerm) -> Sequence[Note]:
    # Bound parameters only: the search term never becomes part of the SQL text.
    pattern = f"%{_escape_like(q)}%"
    stmt = (
        select(Note)
        .where(
            Note.owner_id == user.id,
            or_(Note.title.ilike(pattern, escape="\\"), Note.body.ilike(pattern, escape="\\")),
        )
        .order_by(Note.id)
        .limit(100)
    )
    return db.scalars(stmt).all()


@router.get("/{note_id}", response_model=NoteOut)
def get_note(note_id: NoteId, user: CurrentUser, db: DbSession) -> Note:
    return _owned_note(db, note_id, user)


@router.put("/{note_id}", response_model=NoteOut)
def update_note(note_id: NoteId, payload: NoteUpdate, user: CurrentUser, db: DbSession) -> Note:
    note = _owned_note(db, note_id, user, lock=True)
    if payload.title is not None:
        note.title = payload.title
    if payload.body is not None:
        note.body = payload.body
    # Reload while the row lock is held; the session keeps the values after commit.
    db.flush()
    db.refresh(note)
    db.commit()
    return note


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(note_id: NoteId, user: CurrentUser, db: DbSession) -> Response:
    note = _owned_note(db, note_id, user, lock=True)
    db.delete(note)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
