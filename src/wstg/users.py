"""Users with two roles: admin (may write) and guest (read-only)."""

from __future__ import annotations

import re

from werkzeug.security import check_password_hash, generate_password_hash

from .db import Database, utcnow

ROLES = ("admin", "guest")
MIN_PASSWORD_LENGTH = 12
_USERNAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

# Compared against when the user does not exist, so a login takes the same
# time whether or not the name is valid.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


class UserError(Exception):
    pass


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")


def add(db: Database, username: str, password: str, role: str, actor: str) -> int:
    if not _USERNAME_RE.fullmatch(username):
        raise UserError("user name: 1-64 characters from A-Z a-z 0-9 . _ -")
    if role not in ROLES:
        raise UserError(f"role must be one of {', '.join(ROLES)}")
    _check_password(password)
    with db.tx() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise UserError(f"user exists: {username}")
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, utcnow()))
        db.audit(conn, actor, "user.add", username=username, role=role)
        return cur.lastrowid


def set_password(db: Database, username: str, password: str, actor: str) -> None:
    _check_password(password)
    with db.tx() as conn:
        cur = conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                           (generate_password_hash(password), username))
        if cur.rowcount == 0:
            raise UserError(f"no such user: {username}")
        db.audit(conn, actor, "user.password", username=username)


def set_disabled(db: Database, username: str, disabled: bool, actor: str) -> None:
    with db.tx() as conn:
        u = conn.execute("SELECT role, disabled FROM users WHERE username = ?", (username,)).fetchone()
        if u is None:
            raise UserError(f"no such user: {username}")
        if disabled and u["role"] == "admin":
            others = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND username != ?",
                (username,)).fetchone()[0]
            if others == 0:
                raise UserError("cannot disable the last active admin")
        conn.execute("UPDATE users SET disabled = ? WHERE username = ?", (int(disabled), username))
        db.audit(conn, actor, "user.disable" if disabled else "user.enable", username=username)


def authenticate(db: Database, username: str, password: str) -> dict | None:
    u = db.one("SELECT * FROM users WHERE username = ? AND disabled = 0", (username,))
    if u is None:
        check_password_hash(_DUMMY_HASH, password)
        return None
    return u if check_password_hash(u["password_hash"], password) else None


def get(db: Database, user_id: int) -> dict | None:
    return db.one("SELECT id, username, role FROM users WHERE id = ? AND disabled = 0", (user_id,))


def list_all(db: Database) -> list[dict]:
    return db.query("SELECT id, username, role, disabled, created_at FROM users ORDER BY username")


def can_write(user: dict | None) -> bool:
    return bool(user) and user["role"] == "admin"
