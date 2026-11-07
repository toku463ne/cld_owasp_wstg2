"""ATHN scenarios: auto-run steps read synthetic evidence and show what they should."""
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


def test_athn01_http_login_redirect_and_form_action_scheme(admin_client, store, site):
    put(store, site, "login-http", {
        "stdout.txt": f"301 text/html http://www.example.com/login -> https://www.example.com/login\n"
                      f"200 text/html http://www.example.com/signin -> \n"
                      f"404 text/html http://www.example.com/register -> \n"})
    put(store, site, "auth-pages", {
        "pages/login.html": '<form action="http://www.example.com/login" method="post"></form>',
        "pages/signin.html": '<form action="/account/signin" method="post"></form>'})
    p = page(admin_client, "WSTG-ATHN-01")
    s1 = p.split("Step 1")[1].split("Step 2")[0]
    assert "200 text/html http://www.example.com/signin" in s1      # served over HTTP, no redirect
    assert f"404 text/html http://www.example.com/register" not in s1
    s2 = p.split("Step 2")[1].split("Step 3")[0]
    assert "action=&#34;http://www.example.com/login" in s2 or 'action="http://www.example.com/login' in s2


def test_athn10_lists_only_endpoints_that_answer(admin_client, store, site):
    put(store, site, "alt-auth-endpoints", {
        "stdout.txt": f"200 120 application/json {BASE}/api/v1/login\n"
                      f"404 20 text/html {BASE}/mobile/login\n"
                      f"000 0  {BASE}/graphql\n"
                      f"401 15 application/json {BASE}/oauth/token\n"})
    p = page(admin_client, "WSTG-ATHN-10")
    s1 = p.split("Step 1")[1].split("Step 2")[0]
    assert f"{BASE}/api/v1/login" in s1 and f"{BASE}/oauth/token" in s1
    assert f"{BASE}/mobile/login" not in s1 and f"{BASE}/graphql" not in s1


@pytest.mark.parametrize("tid", [f"WSTG-ATHN-{n:02d}" for n in range(1, 11)])
def test_every_athn_page_renders(admin_client, site, tid):
    assert page(admin_client, tid).count("Step 1") >= 1
