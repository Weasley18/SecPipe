"""Operational CLI: ``python -m secnotes.manage create-user --role admin ...``."""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import select

from secnotes.auth import hash_password
from secnotes.config import Settings
from secnotes.db import Database
from secnotes.logging_config import configure_logging
from secnotes.models import User  # also registers all tables


def _read_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Password: ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secnotes-manage")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="create database tables")
    create = sub.add_parser("create-user", help="create a user (admins can only be created here)")
    create.add_argument("--username", required=True)
    create.add_argument("--role", choices=["user", "admin"], default="user")
    create.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    args = parser.parse_args(argv)

    settings = Settings.from_env()
    configure_logging(settings.log_level)
    database = Database(settings.database_url)
    database.create_all()
    if args.command == "init-db":
        return 0

    password = _read_password(args)
    if len(password) < 12:
        print("password must be at least 12 characters", file=sys.stderr)
        return 2
    username = args.username.lower()
    with database.sessionmaker() as db:
        if db.scalar(select(User).where(User.username == username)) is not None:
            print(f"user {username} already exists", file=sys.stderr)
            return 1
        db.add(User(username=username, password_hash=hash_password(password), role=args.role))
        db.commit()
    print(f"created {args.role} {username}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
