from sqlalchemy import select

from models import Note


def bad_get(db, note_id):
    # ruleid: secnotes-possible-idor
    note = db.get(Note, note_id)
    if note is None:
        raise LookupError
    return note


def bad_select(db, note_id):
    # ruleid: secnotes-possible-idor
    return db.scalar(select(Note).where(Note.id == note_id))


def bad_legacy_query(db, note_id):
    # ruleid: secnotes-possible-idor
    return db.query(Note).get(note_id)


def good_filtered(db, note_id, user):
    # ok: secnotes-possible-idor
    return db.scalar(select(Note).where(Note.id == note_id, Note.owner_id == user.id))


def good_checked(db, note_id, user):
    # ok: secnotes-possible-idor
    note = db.get(Note, note_id)
    if note is None or note.owner_id != user.id:
        raise LookupError
    return note
