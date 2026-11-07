"""IDNT scenarios: auto-run steps on synthetic evidence."""
import json
import shutil

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


def har(*urls):
    return json.dumps({"log": {"entries": [
        {"request": {"method": m, "url": u, "cookies": [{"name": "SID", "value": "SECRET-SID"}]},
         "response": {"status": 200, "content": {"mimeType": "text/html"}}} for m, u in urls]}}).encode()


def test_idnt01_lists_paths_per_role_from_the_har_captions(admin_client, store, site):
    store.add_file(site, "har-browse", har(("GET", f"{BASE}/home"), ("GET", f"{BASE}/js/app.js")),
                   "a.har", "anonymous", "admin")
    store.add_file(site, "har-browse", har(("GET", f"{BASE}/home"), ("POST", f"{BASE}/admin/users/42?x=1"),
                                           ("GET", "https://cdn.example.net/lib")), "b.har", "logged in as operator", "admin")
    p = page(admin_client, "WSTG-IDNT-01")
    step3 = p.split("Step 3")[1].split("Step 4")[0]
    assert "== anonymous\nGET /home\n\n== logged in as operator\nGET /home\nGET https://cdn.example.net/lib\nPOST /admin/users/:id\n" in step3
    assert "app.js" not in step3 and "SECRET-SID" not in p
    prompt = p[p.index('id="ai-prompt"'):]
    assert "POST /admin/users/:id" not in prompt          # HAR-derived output stays out of the prompt


@pytest.mark.skipif(not shutil.which("jq"), reason="jq not installed")
def test_idnt04_public_user_list_emails_and_form_fields(admin_client, store, site):
    put(store, site, "auth-pages", {
        "stdout.txt": f"200 900 text/html {BASE}/login -> \n404 20 text/html {BASE}/register -> \n"
                      f"200 120 application/json {BASE}/wp-json/wp/v2/users -> \n301 0 text/html {BASE}/?author=1 -> {BASE}/author/jdoe/\n",
        "pages/wp-users.json": json.dumps([{"id": 1, "slug": "jdoe", "name": "J Doe"}]),
        "pages/login.html": '<form action="/login" method="post"><input name="username" type="text"><input type="password" name="pw"></form>',
        "pages/register.html": "not found"})
    put(store, site, "http-root-https", {"stdout.txt": "HTTP/1.1 200 OK\r\n",
                                         "body.html": "Contact taro.yamada@corp.example.jp or logo@2x.png"})
    put(store, site, "site-assets", {"site/index.html": "mail hanako.suzuki@corp.example.jp"})
    p = page(admin_client, "WSTG-IDNT-04")
    assert f"404 20 text/html {BASE}/register" not in p.split("Step 1")[1].split("Step 2")[0]
    assert f"-&gt; {BASE}/author/jdoe/" in p and "1\tjdoe\tJ Doe" in p
    assert "taro.yamada@corp.example.jp" in p and "logo@2x.png" not in p.split("Step 3")[1].split("Step 4")[0]
    p = page(admin_client, "WSTG-IDNT-05")
    assert "2 first.last@corp.example.jp" in p
    assert 'login.html:&lt;input name=&#34;username&#34;' in p or "login.html:&lt;input name=\"username\"" in p
