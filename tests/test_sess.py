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
    # Step 2 is the HAR urls check (no HAR evidence here); the 404-body check is now Step 3.
    s3 = p.split("Step 3")[1].split("Step 4")[0]
    assert "PHPSESSID" in s3


@pytest.mark.parametrize("tid", [f"WSTG-SESS-{n:02d}" for n in range(1, 10)])
def test_every_sess_page_renders(admin_client, site, tid):
    assert page(admin_client, tid).count("Step 1") >= 1


def test_sess04_prompt_has_masked_har_views_and_storage_summary(admin_client, store, site):
    import json
    secret = "TOPSECRETsessionVALUE99"
    har_doc = {"log": {"entries": [
        {"request": {"method": "GET", "url": f"{BASE}/home?sid={secret}", "headers": [],
                     "cookies": [{"name": "SESSIONID", "value": secret}]},
         "response": {"status": 200, "headers": [], "content": {"text": "ok"}}}]}}
    state = {"cookies": [{"name": "SESSIONID", "value": secret, "domain": "www.example.com", "path": "/",
                          "secure": True, "httpOnly": True, "sameSite": "Lax"}],
             "origins": [{"origin": BASE, "localStorage": [{"name": "auth_token", "value": secret}]}]}
    store.add_file(site, "har-browse", json.dumps(har_doc).encode(), "user-20260101-1200.har", "", "admin")
    store.add_file(site, "har-browse", json.dumps(state).encode(), "storage-state-user-20260101-1200.json", "", "admin")
    p = page(admin_client, "WSTG-SESS-04")
    prompt = p[p.index('id="ai-prompt"'):]
    assert "TOKEN-IN-URL" in prompt                        # step 2 (wstg-har urls) output is included
    assert "STORAGE-TOKEN localStorage[auth_token]" in prompt   # step 4 (wstg-har expose)
    assert "browser storage state" in prompt and "cookie SESSIONID" in prompt
    assert "SENSITIVE" in prompt
    assert secret not in prompt                            # never a raw value
    assert "session-exposure-tests" not in p               # the manual evidence is gone
