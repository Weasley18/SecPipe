from sqlalchemy import text


def bad_fstring(db, q, uid):
    # ruleid: secnotes-sqlalchemy-raw-sql
    return db.execute(text(f"SELECT * FROM notes WHERE owner_id = {uid} AND title LIKE '%{q}%'"))


def bad_concat(db, q):
    # ruleid: secnotes-sqlalchemy-raw-sql
    return db.execute("SELECT * FROM notes WHERE title = '" + q + "'")


def bad_format(db, q):
    # ruleid: secnotes-sqlalchemy-raw-sql
    return db.execute(text("SELECT * FROM notes WHERE title = '{}'".format(q)))


def good_bound(db, q):
    # ok: secnotes-sqlalchemy-raw-sql
    return db.execute(text("SELECT * FROM notes WHERE title = :q"), {"q": q})
