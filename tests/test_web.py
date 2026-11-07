from conftest import ADMIN_PW, csrf_of, login

from wstg import users


def test_login_required(app):
    c = app.test_client()
    r = c.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert c.get("/admin/users").status_code == 302


def test_login_and_logout(app):
    c = app.test_client()
    r = login(c, "admin", ADMIN_PW)
    assert r.status_code == 302
    page = c.get("/").get_data(as_text=True)
    assert "No test targets yet" in page and "admin" in page
    token = csrf_of(c)
    assert c.post("/logout", data={"csrf": token}).status_code == 302
    assert c.get("/").status_code == 302


def test_bad_login(app, db):
    c = app.test_client()
    r = login(c, "admin", "wrong-password-x")
    assert r.status_code == 200 and "Invalid user name or password" in r.get_data(as_text=True)
    assert db.one("SELECT action FROM audit_log WHERE action = 'login.fail'")


def test_login_needs_csrf(app):
    c = app.test_client()
    c.get("/login")
    r = c.post("/login", data={"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 400


def test_post_without_csrf_rejected(admin_client):
    r = admin_client.post("/admin/users", data={"username": "x", "password": "x-long-password", "role": "guest"})
    assert r.status_code == 400


def test_open_redirect_blocked(app):
    c = app.test_client()
    token = csrf_of(c)
    r = c.post("/login?next=//evil.example.com/", data={"username": "admin", "password": ADMIN_PW, "csrf": token})
    assert r.headers["Location"] == "/"


def test_admin_adds_user(admin_client, db):
    token = csrf_of(admin_client)
    r = admin_client.post("/admin/users", data={"username": "carol", "password": "c-long-password",
                                                 "role": "guest", "csrf": token})
    assert r.status_code == 302
    assert users.authenticate(db, "carol", "c-long-password")


def test_guest_is_read_only(guest_client, db):
    assert guest_client.get("/").status_code == 200
    assert guest_client.get("/admin/users").status_code == 403
    token = csrf_of(guest_client)
    r = guest_client.post("/admin/users", data={"username": "mallory", "password": "m-long-password",
                                                "role": "admin", "csrf": token})
    assert r.status_code == 403
    assert db.one("SELECT 1 FROM users WHERE username = 'mallory'") is None
    assert "Users</a>" not in guest_client.get("/").get_data(as_text=True)


def test_client_network_check(app):
    c = app.test_client()
    assert c.get("/login", headers={"X-Forwarded-For": "192.168.1.20"}).status_code == 200
    assert c.get("/login", headers={"X-Forwarded-For": "10.0.0.5"}).status_code == 403


def test_security_headers(app):
    r = app.test_client().get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert "HttpOnly" in r.headers["Set-Cookie"]


def test_refuses_pending_migrations(cfg, tmp_path):
    import pytest
    from wstg import db as dbmod
    from wstg.web import create_app

    fresh = dbmod.Database(tmp_path / "empty.sqlite3")
    with pytest.raises(RuntimeError, match="pending migrations"):
        create_app(cfg, fresh)
