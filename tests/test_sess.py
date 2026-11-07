"""SESS scenarios: auto-run steps read collected cookie and crawl evidence."""
import pytest

from wstg import evidence as evmod
from wstg import targets as tm

from test_conf import BASE, page, put


@pytest.fixture
def site(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    return tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")


@pytest.fixture
def store(cfg, db):
    return evmod.Store(cfg, db)


SAMPLES = (
    "HTTP/1.1 200 OK\r\n"
    "Set-Cookie: SESSIONID=abc123secret; Path=/; HttpOnly\r\n"
    "Set-Cookie: CSRF=zz; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
    "\r\n"
    "HTTP/1.1 200 OK\r\n"
    "Set-Cookie: SESSIONID=def456secret; Path=/; HttpOnly\r\n"
    "\r\n")


def test_sess01_lists_cookies_with_value_masked(admin_client, store, site):
    put(store, site, "session-token-samples", {"stdout.txt": SAMPLES})
    s1 = page(admin_client, "WSTG-SESS-01").split("Step 1")[1].split("Step 2")[0]
    assert "SESSIONID=&lt;value&gt;" in s1 or "SESSIONID=<value>" in s1
    assert "abc123secret" not in s1               # the real value is masked


def test_sess02_flags_missing_cookie_attributes(admin_client, store, site):
    put(store, site, "session-token-samples", {"stdout.txt": SAMPLES})
    s1 = page(admin_client, "WSTG-SESS-02").split("Step 1")[1].split("Step 2")[0]
    assert "SESSIONID: MISSING Secure,SameSite" in s1
    assert "CSRF: Secure,HttpOnly,SameSite present" in s1


def test_sess04_finds_token_in_url_and_error_body(admin_client, store, site):
    put(store, site, "katana-crawl", {"katana.txt": f"{BASE}/home?jsessionid=TOPSECRET&x=1\n"})
    put(store, site, "site-assets", {"site/app.js": "const t = localStorage.getItem('authToken')"})
    put(store, site, "http-404", {"body.html": "Error: PHPSESSID leaked in trace"})
    p = page(admin_client, "WSTG-SESS-04")
    s1 = p.split("Step 1")[1].split("Step 2")[0]
    assert "jsessionid=&lt;value&gt;" in s1 or "jsessionid=<value>" in s1
    assert "TOPSECRET" not in s1
    s2 = p.split("Step 2")[1].split("Step 3")[0]
    assert "PHPSESSID" in s2


@pytest.mark.parametrize("tid", [f"WSTG-SESS-{n:02d}" for n in range(1, 10)])
def test_every_sess_page_renders(admin_client, site, tid):
    assert page(admin_client, tid).count("Step 1") >= 1
