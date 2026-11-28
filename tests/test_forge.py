"""WSTG-BUSL-02 step 2: parameter forging (forge.py) against a loopback echo app."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from wstg import forge


class Echo(BaseHTTPRequestHandler):
    """Echoes the request's parameters; if role=admin is sent, adds a marker to the body."""
    def log_message(self, *a):
        pass

    def _reply(self, params: dict):
        # A secure server owns price (ignores the client value) but wrongly trusts role:
        # role=admin unlocks an admin page that contains the word "admin".
        if params.get("role", [""])[0] == "admin":
            body = b"welcome admin -- ADMIN PANEL unlocked for you"
        else:
            body = b"home page, nothing special here"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(parse_qs(urlsplit(self.path).query, keep_blank_values=True))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self._reply(parse_qs(self.rfile.read(n).decode(), keep_blank_values=True))


@pytest.fixture
def serve():
    srvs = []

    def start():
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        srvs.append(srv)
        return f"http://127.0.0.1:{srv.server_port}"
    yield start
    for s in srvs:
        s.shutdown()


def _har(tmp_path, base, entries):
    d = tmp_path / "har-browse" / "items"
    d.mkdir(parents=True)
    (d / "001-user-20260101.har").write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}))
    return tmp_path / "har-browse"


def _post_entry(base, path, body):
    return {"request": {"method": "POST", "url": base + path, "headers": [
        {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}, {"name": "Cookie", "value": "sid=abc"}],
        "postData": {"mimeType": "application/x-www-form-urlencoded",
                     "params": [{"name": k, "value": v} for k, v in body]}}, "response": {"headers": []}}


def test_list_gathers_requests_and_params(tmp_path, serve, capsys):
    base = serve()
    har = _har(tmp_path, base, [
        _post_entry(base, "/cart/update", [("item", "7"), ("qty", "1")]),
        {"request": {"method": "GET", "url": base + "/profile?userId=5", "headers": []}, "response": {"headers": []}},
        {"request": {"method": "GET", "url": base + "/style.css", "headers": []}, "response": {"headers": []}},
    ])
    rc = forge.main(["--base", base + "/", "--har", str(har), "--list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "POST /cart/update" in out and "GET /profile" in out
    assert "/style.css" not in out                     # static dropped
    assert "price role isAdmin" in out.replace("  ", " ") or "price" in out


def test_forge_overrides_body_param_and_detects_echo(tmp_path, serve, capsys):
    base = serve()
    har = _har(tmp_path, base, [_post_entry(base, "/cart/checkout", [("item", "7"), ("price", "999")])])
    rc = forge.main(["--base", base + "/", "--har", str(har), "--request", "1",
                     "--param", "price=1", "--param", "role=admin", "--agree"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "baseline" in out
    assert "overrode price='1'" in out and "same length" in out     # server ignores client price
    assert "added role='admin'" in out and "value echoed" in out    # role=admin unlocks the admin page


def test_send_needs_agree(tmp_path, serve):
    base = serve()
    har = _har(tmp_path, base, [_post_entry(base, "/cart", [("item", "7")])])
    assert forge.main(["--base", base + "/", "--har", str(har), "--request", "1", "--param", "price=1"]) == 2


def test_request_out_of_range(tmp_path, serve):
    base = serve()
    har = _har(tmp_path, base, [_post_entry(base, "/cart", [("item", "7")])])
    assert forge.main(["--base", base + "/", "--har", str(har), "--request", "9",
                       "--param", "price=1", "--agree"]) == 2


def test_run_variants_marks_added_vs_overridden(tmp_path, serve):
    base = serve()
    har = _har(tmp_path, base, [_post_entry(base, "/cart", [("price", "999")])])
    reqs = forge.gather_requests(base, har)
    baseline, results = forge.run_variants(reqs[0], [("price", "1"), ("role", "admin")], repeat=1, pause=0)
    assert baseline.status == 200
    by = {r.name: r for r in results}
    assert not by["price"].added and by["role"].added
    assert by["role"].echoed and not by["price"].echoed


# ---- web Tools tab -----------------------------------------------------------------

from datetime import date, timedelta
from conftest import csrf_of
from wstg import forge_run as frun
from wstg import targets as tm


@pytest.fixture
def web_site(db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    today = date.today()
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="AUTH-1",
                    valid_from=str(today - timedelta(days=1)), valid_until=str(today + timedelta(days=30)),
                    actor="test")
    return tm.get(db, "www.example.com")


def _put_har(cfg, t, n=1):
    d = tm.evidence_dir(cfg, t) / "har-browse" / "v0001" / "items"
    d.mkdir(parents=True)
    entries = []
    for i in range(n):
        entries.append({"request": {"method": "POST", "url": f"https://www.example.com/cart/checkout{i}",
                 "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                 "postData": {"mimeType": "application/x-www-form-urlencoded",
                              "params": [{"name": "item", "value": "7"}, {"name": "price", "value": "999"}]}},
                 "response": {"headers": []}})
    (d / "001-user-20260101.har").write_text(json.dumps({"log": {"entries": entries}}))
    (tm.evidence_dir(cfg, t) / "har-browse" / "latest").symlink_to("v0001")


REAL = frun.command


@pytest.fixture
def sleeper(monkeypatch):
    seen = []

    def command(cfg, t, base_url, requests, params, stop_file):
        seen.append(REAL(cfg, t, base_url, requests, params, stop_file))
        return ["sleep", "30"]
    monkeypatch.setattr(frun, "command", command)
    return seen


def post(client, path, **data):
    data["csrf"] = csrf_of(client)
    return client.post(path, data=data)


def test_command_builds_requests_and_params(cfg, web_site):
    _put_har(cfg, web_site, n=3)
    argv = frun.command(cfg, web_site, "https://www.example.com", [1, 3],
                        ["price=1", "role=admin"], frun.folder(cfg, web_site) / "stop")
    assert "--agree" in argv and "--stop-file" in argv
    assert argv.count("--request") == 2 and "--all" not in argv
    assert argv[argv.index("--param") + 1] == "price=1"
    # no requests chosen -> --all
    argv2 = frun.command(cfg, web_site, "https://www.example.com", [], ["price=1"], frun.folder(cfg, web_site) / "stop")
    assert "--all" in argv2 and "--request" not in argv2


def test_web_forge_page_lists_and_guards(admin_client, guest_client, cfg, web_site):
    _put_har(cfg, web_site)
    assert "Parameter forging" in admin_client.get("/t/www.example.com/tools").get_data(as_text=True)
    page = admin_client.get("/t/www.example.com/tools/forge").get_data(as_text=True)
    assert "cart/checkout" in page and "price=1" in page and "Send baseline and forged" in page
    assert "Send baseline and forged" not in guest_client.get("/t/www.example.com/tools/forge").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/tools/forge/start", request="1", agree="1").status_code == 403


def test_web_forge_start_stop(admin_client, cfg, web_site, sleeper):
    _put_har(cfg, web_site, n=3)
    # agreement required
    post(admin_client, "/t/www.example.com/tools/forge/start", request="1")
    assert frun.status(cfg, web_site) is None and not sleeper
    r = post(admin_client, "/t/www.example.com/tools/forge/start", request=["1", "3"], agree="1")
    assert r.status_code == 302
    try:
        assert sleeper[0].count("--request") == 2
        page = admin_client.get("/t/www.example.com/tools/forge").get_data(as_text=True)
        assert "Forge batch running" in page and ">Stop</button>" in page and 'http-equiv="refresh"' in page
        post(admin_client, "/t/www.example.com/tools/forge/stop", how="stop")
        assert frun.status(cfg, web_site)["stop_request"]
    finally:
        frun.kill(cfg, web_site)


def test_web_forge_all_when_none_selected(admin_client, cfg, web_site, sleeper):
    _put_har(cfg, web_site, n=2)
    r = post(admin_client, "/t/www.example.com/tools/forge/start", agree="1", params="price=1")
    assert r.status_code == 302
    try:
        assert "--all" in sleeper[0]
    finally:
        frun.kill(cfg, web_site)


def test_web_forge_without_har(admin_client, cfg, web_site):
    page = admin_client.get("/t/www.example.com/tools/forge").get_data(as_text=True)
    assert "No logged-in capture yet" in page


def test_add_finished_batch_to_evidence(admin_client, cfg, db, web_site):
    import time as _t
    d = frun.folder(cfg, web_site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "label": "2 request(s)", "params": ["price=1"],
                                              "started": "2026-01-01T00:00:00Z", "started_ts": _t.time()}))
    (d / "forge.log").write_text(
        "# started\n[1/2] #1 POST /cart\n  baseline       : 200 - 10 bytes\n  overrode price=1: 200, same length\n")
    st = frun.status(cfg, web_site)
    assert st["finished"] and not st["running"]
    r = post(admin_client, "/t/www.example.com/tools/forge/add", caption="batch 1")
    assert r.status_code == 302
    from wstg import evidence as evmod
    v = evmod.Store(cfg, db).load("www.example.com", "forge-request-tests")
    assert v and "forge batch" in (v.path / v.items[0].file).read_text()


def test_links_to_the_forge_tool(admin_client, web_site):
    page = admin_client.get("/t/www.example.com/evidence/forge-request-tests").get_data(as_text=True)
    assert "/t/www.example.com/tools/forge" in page


def test_forge_header_shows_param_names(tmp_path, serve, capsys):
    """Same-path requests must be told apart in the evidence by their parameters."""
    base = serve()
    har = _har(tmp_path, base, [
        _post_entry(base, "/app.aspx", [("action", "save"), ("xslFile", "a")]),
        _post_entry(base, "/app.aspx", [("action", "del"), ("code", "x")]),
    ])
    forge.main(["--base", base + "/", "--har", str(har), "--all", "--param", "price=1", "--agree"])
    out = capsys.readouterr().out
    assert "#1 POST /app.aspx  params=action,xslFile" in out
    assert "#2 POST /app.aspx  params=action,code" in out


def _cfg_with_proxy():
    import dataclasses
    from wstg import config as cfgmod
    from pathlib import Path
    base = cfgmod.Config(evidence_root=Path("/tmp/x"), db_path=Path("/tmp/x.db"))
    return dataclasses.replace(base, http_proxy="http://127.0.0.1:3128")


def test_proxy_env_sets_proxy_from_config():
    import dataclasses
    from wstg import capture_run
    import os
    os.environ["no_proxy"] = "localhost"
    base = _cfg_with_proxy()
    env = capture_run.proxy_env(base)
    assert env["http_proxy"] == "http://127.0.0.1:3128" and env["https_proxy"] == "http://127.0.0.1:3128"
    assert "no_proxy" not in env and "NO_PROXY" not in env


def test_forge_start_passes_proxy_env(cfg, web_site):
    _put_har(cfg, web_site)
    import dataclasses
    paced = dataclasses.replace(cfg, http_proxy="http://127.0.0.1:3128")
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            seen["env"] = kw.get("env")
            self.pid = 424242
    frun.start(paced, web_site, base_url="https://www.example.com", requests=[1],
               params=["price=1"], actor="admin", popen=FakePopen)
    assert seen["env"]["http_proxy"] == "http://127.0.0.1:3128"
