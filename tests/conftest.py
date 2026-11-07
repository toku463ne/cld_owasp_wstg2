import re
from pathlib import Path

import pytest

from wstg import config, db as dbmod, users
from wstg.web import create_app

ADMIN_PW = "admin-password-123"
GUEST_PW = "guest-password-123"


@pytest.fixture
def cfg(tmp_path: Path) -> config.Config:
    env = {
        "WSTG_EVIDENCE_ROOT": str(tmp_path / "evidence"),
        "WSTG_DB_PATH": str(tmp_path / "db" / "wstg.sqlite3"),
        "WSTG_SECRET_KEY": "test-secret",
    }
    c = config.load(env)
    config.ensure_dirs(c)
    return c


@pytest.fixture
def db(cfg) -> dbmod.Database:
    d = dbmod.Database(cfg.db_path)
    dbmod.migrate(d)
    yield d
    d.close()


@pytest.fixture
def app(cfg, db):
    users.add(db, "admin", ADMIN_PW, "admin", actor="test")
    users.add(db, "guest", GUEST_PW, "guest", actor="test")
    a = create_app(cfg, db)
    a.config["TESTING"] = True
    return a


def csrf_of(client) -> str:
    html = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf" content="([^"]+)"', html).group(1)


def login(client, username: str, password: str):
    token = csrf_of(client)
    return client.post("/login", data={"username": username, "password": password, "csrf": token})


@pytest.fixture
def admin_client(app):
    c = app.test_client()
    assert login(c, "admin", ADMIN_PW).status_code == 302
    return c


@pytest.fixture
def guest_client(app):
    c = app.test_client()
    assert login(c, "guest", GUEST_PW).status_code == 302
    return c
