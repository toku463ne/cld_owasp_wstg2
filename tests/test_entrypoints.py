"""Entry point probe (WSTG-INFO-06 step 3) against a test server on loopback only."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import csrf_of

from wstg import catalog as catmod
from wstg import entrypoints
from wstg import evidence as evmod
from wstg import runner as rmod
from wstg import targets as tm

SESSION = "s3cr3t-session-abc123"
LOGIN_FORM = b'<form action="/login" method="post"><input name="user"><input type="password" name="pass">' \
             b'<input type="hidden" name="_token" value="deadbeefcsrf"><input type="submit" value="Go"></form>'


class Handler(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Handler.seen.append((self.path, "SID" in (self.headers.get("Cookie") or "")))
        logged_in = f"SID={SESSION}" in (self.headers.get("Cookie") or "")
        if self.path == "/myaccount" and not logged_in:
            return self._send(302, b"", location="/login?next=/myaccount")
        pages = {
            "/login": LOGIN_FORM,
            "/myaccount": b'<h1>Account</h1><form method="post" action="/avatar" enctype="multipart/form-data">'
                          b'<input type="file" name="avatar"><input name="nick" value="bob"></form>' + b"x" * 500,
            "/reports": b"<h1>Reports</h1>" + b"y" * 3000,          # open to everyone, seen only logged in
            "/admin": b"",
        }
        if self.path == "/admin":
            return self._send(403, b"forbidden")
        body = pages.get(self.path.split("?")[0])
        if body is None:
            return self._send(404, b"not found")
        self._send(200, body)

    def _send(self, code, body, location=""):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    Handler.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _har_entry(url, cookies=()):
    return {"request": {"method": "GET", "url": url, "headers": [],
                        "cookies": [{"name": c, "value": SESSION} for c in cookies]},
            "response": {"status": 200, "headers": []}}


def _folders(tmp_path, base):
    lst = tmp_path / "list" / "items"
    lst.mkdir(parents=True)
    (lst / "001.txt").write_text("/login\n/myaccount\n# a comment\nhttps://other.example.org/x\n")
    har = tmp_path / "har" / "items"
    har.mkdir(parents=True)
    (har / "001-anon-20261108-052427.har").write_text(json.dumps({"log": {"entries": [
        _har_entry(base + "/login")]}}))
    (har / "002-user-20261108-052526.har").write_text(json.dumps({"log": {"entries": [
        _har_entry(base + "/reports?year=2026", ["SID"]), _har_entry(base + "/logout", ["SID"]),
        _har_entry(base + "/static/app.js", ["SID"])]}}))
    (har / "003-storage-state-user-20261108-052526.json").write_text(json.dumps({"cookies": [
        {"name": "SID", "value": SESSION, "domain": "127.0.0.1", "path": "/", "expires": -1, "secure": False}]}))
    ffuf = tmp_path / "ffuf"
    ffuf.mkdir()
    (ffuf / "ffuf-content.json").write_text(json.dumps({"results": [
        {"url": base + "/admin", "status": 403}, {"url": "https://evil.example.net/x", "status": 200}]}))
    return {"list": lst.parent, "har": har.parent, "ffuf": ffuf}


def test_probe_reports_login_forms_and_contacts_only_the_base_host(tmp_path, server, capsys):
    f = _folders(tmp_path, server)
    rc = entrypoints.main(["--base", server + "/", "--list", str(f["list"]), "--har", str(f["har"]),
                           "--ffuf", str(f["ffuf"]), "--katana", str(tmp_path / "missing")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "katana-crawl not collected" in out and "logged-in sessions (browser storage state of `wstg capture`): user" in out
    assert "list: https://other.example.org/x is not on 127.0.0.1; skipped" in out
    blocks = {b.split("   [")[0]: b for b in out.split("\n== ")[1:]}
    assert "login: yes (refused or sent to login without cookies)" in blocks["/myaccount"]
    assert "-> /login?next=/myaccount" in blocks["/myaccount"]
    assert "form: POST /avatar; fields: nick; FILE UPLOAD: avatar" in blocks["/myaccount"]
    assert "form: POST /login; fields: user, pass; hidden: _token" in blocks["/login"]
    assert "login: OPEN" in blocks["/reports"] and "params: query: year" in blocks["/reports"]
    assert "login: yes" in blocks["/admin"] and "sources: ffuf" in blocks["/admin"]
    assert "skipped: looks state-changing" in blocks["/logout"]
    # no value of a cookie or a field ever appears; never contacted: logout, static, other hosts
    for secret in (SESSION, "deadbeefcsrf", "bob"):
        assert secret not in out
    paths = {p for p, _ in Handler.seen}
    assert "/logout" not in paths and "/static/app.js" not in paths
    assert ("/myaccount", True) in Handler.seen and ("/myaccount", False) in Handler.seen


def test_probe_limit_and_no_answer(tmp_path, capsys):
    f = tmp_path / "ffuf"
    f.mkdir()
    base = "http://127.0.0.1:9"          # discard port: nothing listens
    (f / "ffuf-content.json").write_text(json.dumps({"results": [{"url": f"{base}/p{i}", "status": 200}
                                                                 for i in range(5)]}))
    rc = entrypoints.main(["--base", base + "/", "--ffuf", str(f), "--max", "2"])
    out = capsys.readouterr().out
    assert "2 probed, 3 over the limit of 2" in out and "== not probed" in out
    assert rc == 4                                                   # nothing answered: failed collection


def test_catalog_entry_points_is_automatic_and_scope_checked(cfg, db):
    from wstg import catalog as catmod
    cat = catmod.load()
    ev = cat.evidence["entry-points"]
    assert ev.kind == "auto" and "entry-point-list" in ev.inputs and "har-browse" in ev.inputs
    site = tm.create(db, cfg, "www.example.com", "fqdn")
    tm.update_scope(db, site, allowed_hosts="www.example.com", allowed_ports="443", base_url="https://www.example.com",
                    authorization_ref="Contract 2026-001", valid_from="2000-01-01", valid_until="2099-12-31",
                    actor="test")
    scope = tm.get_scope(db, site)
    argv, _, _ = rmod.build_argv(ev, tm.placeholder_values(cfg, site, scope) | {"out": "/tmp/x"}, "", 0,
                                 rmod.input_paths(cfg, site, ev, cat))
    assert tm.contacted(argv, site) == [("www.example.com", 443)]
    tm.check_command(site, scope, argv, passive=False)


def post(client, url, **data):
    data["csrf"] = csrf_of(client)
    return client.post(url, data=data)


def test_save_and_collect_button(admin_client, guest_client, cfg, db):
    site = tm.create(db, cfg, "www.example.com", "fqdn")
    tm.update_scope(db, site, allowed_hosts="www.example.com", allowed_ports="443", base_url="https://www.example.com",
                    authorization_ref="Contract 2026-001", valid_from="2000-01-01", valid_until="2099-12-31",
                    actor="test")
    url = "/t/www.example.com/wstg/WSTG-INFO-06"
    page = admin_client.get(url).get_data(as_text=True)
    assert "Save and collect" in page and "/steps/3/collect" in page
    assert "/steps/3/collect" not in guest_client.get(url).get_data(as_text=True)
    assert post(guest_client, url + "/steps/3/collect", text="/login").status_code == 403
    assert post(admin_client, url + "/steps/2/collect", text="/login").status_code == 404
    r = post(admin_client, url + "/steps/3/collect", text="/login\r\n/myaccount\r\n")
    assert r.status_code == 302
    store = evmod.Store(cfg, db)
    v = store.load(site.name, "entry-point-list")
    assert (v.path / v.items[0].file).read_text() == "/login\n/myaccount"
    job = rmod.last_job(db, site)
    assert job["evidence_id"] == "entry-points" and job["force"] == 1
    assert [i["evidence_id"] for i in rmod.job_items(db, job["id"])] == ["entry-points"]
    page = admin_client.get(url).get_data(as_text=True)
    assert "/login\n/myaccount</textarea>" in page
    assert f"Last collection (job {job['id']})" in page and "queued, waiting for the worker" in page
    # the same text again: no new version (the job is still queued, so it is refused)
    r = post(admin_client, url + "/steps/3/collect", text="/login\n/myaccount")
    assert store.load(site.name, "entry-point-list").version == v.version
    assert "still active" in admin_client.get(url).get_data(as_text=True)


def test_collect_status_shows_a_failure_and_the_step_explains_a_missing_result(admin_client, cfg, db):
    site = tm.create(db, cfg, "www.example.com", "fqdn")
    tm.update_scope(db, site, allowed_hosts="www.example.com", allowed_ports="443", base_url="https://www.example.com",
                    authorization_ref="Contract 2026-001", valid_from="2000-01-01", valid_until="2099-12-31",
                    actor="test")
    store = evmod.Store(cfg, db)
    store.add_text(site, "entry-points", "old hand-made table", "", "admin")     # a manual version from before
    job = rmod.enqueue(db, catmod.load(), site, "", "admin", evidence_id="entry-points", force=True)
    with db.tx() as conn:
        conn.execute("UPDATE job_items SET status='failed', finished_at='2026-11-21T13:09:31Z',"
                     " message='tool not installed: wstg-entry' WHERE job_id=?", (job,))
    page = admin_client.get("/t/www.example.com/wstg/WSTG-INFO-06").get_data(as_text=True)
    assert "failed 2026-11-21T13:09:31Z: tool not installed: wstg-entry" in page
    assert "No probe result in this version of entry-points" in page
