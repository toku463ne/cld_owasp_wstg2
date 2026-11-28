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


def _put_har(cfg, t):
    d = tm.evidence_dir(cfg, t) / "har-browse" / "v0001" / "items"
    d.mkdir(parents=True)
    entry = {"request": {"method": "POST", "url": "https://www.example.com/cart/checkout",
             "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
             "postData": {"mimeType": "application/x-www-form-urlencoded",
                          "params": [{"name": "item", "value": "7"}, {"name": "price", "value": "999"}]}},
             "response": {"headers": []}}
    (d / "001-user-20260101.har").write_text(json.dumps({"log": {"entries": [entry]}}))
    (tm.evidence_dir(cfg, t) / "har-browse" / "latest").symlink_to("v0001")


def post(client, path, **data):
    data["csrf"] = csrf_of(client)
    return client.post(path, data=data)


def test_web_forge_page_lists_and_guards(admin_client, guest_client, cfg, web_site):
    _put_har(cfg, web_site)
    assert "Parameter forging" in admin_client.get("/t/www.example.com/tools").get_data(as_text=True)
    page = admin_client.get("/t/www.example.com/tools/forge").get_data(as_text=True)
    assert "POST" in page and "/cart/checkout" in page and "price=1" in page
    assert "Send baseline and forged" not in guest_client.get("/t/www.example.com/tools/forge").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/tools/forge", action="send", request="1",
                params="price=1", agree="1").status_code == 403
    # agreement required
    r = post(admin_client, "/t/www.example.com/tools/forge", action="send", request="1", params="price=1")
    assert r.status_code == 400 and "tick the box" in r.get_data(as_text=True)


def test_web_forge_without_har(admin_client, cfg, web_site):
    page = admin_client.get("/t/www.example.com/tools/forge").get_data(as_text=True)
    assert "No logged-in capture yet" in page


def test_links_to_the_forge_tool(admin_client, web_site):
    page = admin_client.get("/t/www.example.com/evidence/forge-request-tests").get_data(as_text=True)
    assert "/t/www.example.com/tools/forge" in page

def test_forge_text_and_save_to_evidence(admin_client, cfg, db, web_site):
    from wstg import web_tools, evidence as evmod
    from wstg.entrypoints import Answer
    r = forge.Req("POST", "https://www.example.com/cart/checkout", role="user")
    baseline = Answer(200, 31, "text/html", "", "home page")
    results = [forge.Result("price", "1", False, Answer(200, 31, "text/html", "", "home page"), False),
               forge.Result("role", "admin", True, Answer(200, 28, "text/html", "", "welcome admin"), True)]
    text = web_tools.forge_text(r, baseline, results, "admin")
    assert "wstg forge: POST" in text and "overrode price=1" in text and "added role=admin: 200" in text
    assert "VALUE ECHOED" in text and "same length" in text
    token = web_tools.put_pending(cfg, web_site, "forge-request-tests", text, "forge 1")
    r2 = post(admin_client, "/t/www.example.com/tools/forge", action="save", pending=token, caption="forge 1")
    assert "Added to" in r2.get_data(as_text=True)
    v = evmod.Store(cfg, db).load("www.example.com", "forge-request-tests")
    assert v and "VALUE ECHOED" in (v.path / v.items[0].file).read_text()
