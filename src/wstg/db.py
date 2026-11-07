"""SQLite access and explicit schema migrations.

Migrations are numbered SQL files in `migrations/` (`NNNN_name.sql`), applied
in order and recorded in `schema_migrations`. Before applying migrations to a
database that already has a schema, a copy is taken next to it.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_MIGRATION_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


def utcnow() -> str:
    """UTC timestamp as ISO 8601 text (what the database stores)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Database:
    """One connection per thread (the web server is threaded)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._local = threading.local()

    def connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=True)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA busy_timeout = 30000")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
        self._local.conn = None

    @contextmanager
    def tx(self):
        """A write transaction. BEGIN IMMEDIATE takes the write lock up front,
        so two writers never deadlock on a lock upgrade."""
        conn = self.connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def query(self, sql: str, args=()) -> list[dict]:
        return [dict(r) for r in self.connect().execute(sql, args).fetchall()]

    def one(self, sql: str, args=()) -> dict | None:
        row = self.connect().execute(sql, args).fetchone()
        return dict(row) if row else None

    @staticmethod
    def audit(conn: sqlite3.Connection, actor: str, action: str, **detail) -> None:
        conn.execute(
            "INSERT INTO audit_log (at, actor, action, detail) VALUES (?, ?, ?, ?)",
            (utcnow(), actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True)),
        )


def available_migrations() -> list[tuple[str, Path]]:
    out = []
    for p in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = _MIGRATION_RE.match(p.name)
        if not m:
            raise RuntimeError(f"bad migration file name: {p.name}")
        out.append((m.group(1), p))
    return out


def applied_migrations(db: Database) -> set[str]:
    conn = db.connect()
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone()
    if not exists:
        return set()
    return {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}


def pending_migrations(db: Database) -> list[tuple[str, Path]]:
    done = applied_migrations(db)
    return [(v, p) for v, p in available_migrations() if v not in done]


def _has_tables(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone() is not None


def backup(db: Database, dest: Path) -> Path:
    """Consistent copy of the live database (SQLite online backup API)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    target = sqlite3.connect(dest)
    try:
        db.connect().backup(target)
    finally:
        target.close()
    return dest


def migrate(db: Database) -> list[str]:
    """Apply pending migrations. Returns the versions applied."""
    pending = pending_migrations(db)
    if not pending:
        return []
    conn = db.connect()
    if _has_tables(conn):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup(db, db.path.with_name(f"{db.path.name}.pre-{pending[0][0]}-{stamp}.bak"))
    conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)""")
    applied = []
    for version, path in pending:
        script = path.read_text()
        # executescript commits on its own, so the migration and its record
        # are wrapped in one explicit transaction inside the script.
        try:
            conn.executescript(
                "BEGIN IMMEDIATE;\n" + script + "\n"
                + f"INSERT INTO schema_migrations (version, name, applied_at) "
                  f"VALUES ('{version}', '{path.stem}', '{utcnow()}');\nCOMMIT;"
            )
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        applied.append(version)
    return applied
