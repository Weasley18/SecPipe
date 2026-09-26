"""Notes CRUD and search. Every query is scoped to the caller's own notes."""

from __future__ import annotations

from collections.abc import Sequence

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import or_, select

from secnotes.auth import CurrentUser, DbSession
from secnotes.models import Note, User
from secnotes.schemas import NoteCreate, NoteOut, NoteUpdate

router = APIRouter(prefix="/notes", tags=["notes"])


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _owned_note(db: DbSession, note_id: int, user: User) -> Note:
    note = db.scalar(select(Note).where(Note.id == note_id, Note.owner_id == user.id))
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
    db.commit()
    db.refresh(note)
    return note


@router.get("/search", response_model=list[NoteOut])
def search_notes(user: CurrentUser, db: DbSession, q: str = Query(min_length=1, max_length=100)) -> Sequence[Note]:
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
def get_note(note_id: int, user: CurrentUser, db: DbSession) -> Note:
    return _owned_note(db, note_id, user)


@router.put("/{note_id}", response_model=NoteOut)
def update_note(note_id: int, payload: NoteUpdate, user: CurrentUser, db: DbSession) -> Note:
    note = _owned_note(db, note_id, user)
    if payload.title is not None:
        note.title = payload.title
    if payload.body is not None:
        note.body = payload.body
    db.commit()
    db.refresh(note)
    return note


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(note_id: int, user: CurrentUser, db: DbSession) -> Response:
    note = _owned_note(db, note_id, user)
    db.delete(note)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
