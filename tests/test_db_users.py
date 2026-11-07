import pytest

from wstg import db as dbmod, users


def test_migrate_is_idempotent(db):
    assert dbmod.pending_migrations(db) == []
    assert dbmod.migrate(db) == []
    assert "0001" in dbmod.applied_migrations(db)


def test_migrate_backs_up_existing_schema(cfg, db, monkeypatch, tmp_path):
    extra = tmp_path / "migrations"
    extra.mkdir()
    for _, p in dbmod.available_migrations():
        (extra / p.name).write_text(p.read_text())
    (extra / "9999_extra.sql").write_text("CREATE TABLE extra (id INTEGER PRIMARY KEY);")
    monkeypatch.setattr(dbmod, "MIGRATIONS_DIR", extra)
    assert dbmod.migrate(db) == ["9999"]
    assert list(cfg.db_path.parent.glob("*.pre-9999-*.bak"))


def test_failed_migration_rolls_back(db, monkeypatch, tmp_path):
    extra = tmp_path / "migrations"
    extra.mkdir()
    for _, p in dbmod.available_migrations():
        (extra / p.name).write_text(p.read_text())
    (extra / "9999_bad.sql").write_text("CREATE TABLE half (id INTEGER);\nTHIS IS NOT SQL;")
    monkeypatch.setattr(dbmod, "MIGRATIONS_DIR", extra)
    with pytest.raises(Exception):
        dbmod.migrate(db)
    assert not db.connect().in_transaction
    assert db.one("SELECT name FROM sqlite_master WHERE name='half'") is None
    assert "9999" not in dbmod.applied_migrations(db)


def test_users(db):
    users.add(db, "alice", "a-long-password", "admin", actor="t")
    users.add(db, "bob", "b-long-password", "guest", actor="t")
    assert users.authenticate(db, "alice", "a-long-password")["role"] == "admin"
    assert users.authenticate(db, "alice", "wrong") is None
    assert users.authenticate(db, "nobody", "a-long-password") is None
    with pytest.raises(users.UserError, match="exists"):
        users.add(db, "alice", "a-long-password", "guest", actor="t")
    with pytest.raises(users.UserError, match="at least"):
        users.add(db, "carol", "short", "guest", actor="t")
    with pytest.raises(users.UserError, match="role"):
        users.add(db, "carol", "c-long-password", "editor", actor="t")
    with pytest.raises(users.UserError, match="user name"):
        users.add(db, "bad name", "c-long-password", "guest", actor="t")

    users.set_disabled(db, "bob", True, actor="t")
    assert users.authenticate(db, "bob", "b-long-password") is None
    with pytest.raises(users.UserError, match="last active admin"):
        users.set_disabled(db, "alice", True, actor="t")

    users.set_password(db, "alice", "new-long-password", actor="t")
    assert users.authenticate(db, "alice", "new-long-password")
    actions = [r["action"] for r in db.query("SELECT action FROM audit_log ORDER BY id")]
    assert actions == ["user.add", "user.add", "user.disable", "user.password"]


def test_backup_command_keeps_newest(tmp_path, monkeypatch):
    import sqlite3
    from wstg import cli
    env = tmp_path / "wstg2.env"
    env.write_text(f"WSTG_EVIDENCE_ROOT={tmp_path}/data/evidence\nWSTG_DB_PATH={tmp_path}/data/db/w.sqlite3\n"
                   "WSTG_SECRET_KEY=x\n")
    monkeypatch.setenv("WSTG_CONFIG", str(env))
    assert cli.main(["migrate"]) == 0
    dest = tmp_path / "bk"
    for i in range(3):
        (dest).mkdir(exist_ok=True)
        (dest / f"w-2020010{i}T000000Z.sqlite3").write_bytes(b"old")
    assert cli.main(["backup", "--dest", str(dest), "--keep", "2"]) == 0
    files = sorted(dest.glob("w-*.sqlite3"))
    assert len(files) == 2
    con = sqlite3.connect(files[-1])
    assert con.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] >= 5
