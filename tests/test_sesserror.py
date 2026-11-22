"""Malformed-input error probes (WSTG-SESS-04 step 5) against a loopback target."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from wstg import sessionscan, sesserror

TOKEN = "sessTOKENvalue1234567890"


class App(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def _send(self, code, body: str):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        App.seen.append(("GET", self.path, self.headers.get("Cookie", "")))
        sp = urlsplit(self.path)
        q = parse_qs(sp.query, keep_blank_values=True)
        if sp.path == "/item":
            if "id[]" in q:     # leaky: a type error dumps the cookie and a trace
                self._send(500, f"<pre>Traceback (most recent call last):\n  TypeError\nHTTP_COOKIE={self.headers.get('Cookie')}</pre>")
            elif "id" not in q:
                self._send(400, "missing id")
            else:
                self._send(200, "item")
        elif sp.path == "/search":
            self._send(400 if "q" not in q or len(q["q"][0]) > 100 else 200, "bad request")
        else:
            self._send(404, "not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        App.seen.append(("POST", self.path, body.decode()))
        try:
            json.loads(body)
            self._send(200, "{}")
        except ValueError:
            self._send(400, '{"error": "invalid json"}')


@pytest.fixture
def app():
    App.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _entry(method, url, body=None):
    req = {"method": method, "url": url, "headers": [{"name": "Cookie", "value": f"PHPSESSID={TOKEN}"}],
           "cookies": [{"name": "PHPSESSID", "value": TOKEN}]}
    if body is not None:
        req["postData"] = {"mimeType": "application/json", "text": body}
    return {"request": req, "response": {"status": 200, "headers": []}}


def _har(tmp_path, base, entries, role="user"):
    d = tmp_path / "har"
    d.mkdir(exist_ok=True)
    (d / f"001-{role}-20260101-1200.har").write_text(json.dumps({"log": {"entries": entries}}))
    return d


def test_probes_flag_token_echo_and_trace(tmp_path, app, capsys):
    d = _har(tmp_path, app, [
        _entry("GET", f"{app}/item?id=1"),
        _entry("GET", f"{app}/item?id=2"),            # same template: probed once
        _entry("GET", f"{app}/search?q=a"),
        _entry("POST", f"{app}/api/save", '{"a": 1}'),
        _entry("GET", f"{app}/logout?next=/"),         # state-changing: skipped
        _entry("GET", "https://cdn.example.com/x?y=1"),  # other host: never contacted
        _entry("GET", f"{app}/app.js?v=1"),           # static: skipped
    ])
    rc = sessionscan.main(["--errors", "--base", app + "/", "--har", str(d)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ERROR-ECHO" in out and "DEBUG-OUTPUT python traceback" in out
    assert "verdict: FAIL" in out
    assert TOKEN not in out                         # masked
    assert "GET /logout" in out and "not probed" in out
    paths = [p for _, p, _ in App.seen]
    assert not any("logout" in p or "app.js" in p for p in paths)
    assert sum(1 for p in paths if p.startswith("/item")) == 4
    assert any(m == "POST" and b == '{"wstg_probe": ' for m, _, b in App.seen)
    assert any("/wstg-missing-probe/" in p for p in paths)
    assert all(TOKEN in c for m, _, c in App.seen if m == "GET")   # the session rides along


def test_clean_app_passes(tmp_path, app, capsys):
    d = _har(tmp_path, app, [_entry("GET", f"{app}/search?q=a")])
    assert sessionscan.main(["--errors", "--base", app + "/", "--har", str(d)]) == 0
    out = capsys.readouterr().out
    assert "verdict: no token echo or debug output" in out


def test_no_logged_in_har_is_exit_3(tmp_path, app):
    d = _har(tmp_path, app, [_entry("GET", f"{app}/search?q=a")], role="anon")
    assert sessionscan.main(["--errors", "--base", app + "/", "--har", str(d)]) == 3


def test_no_answer_is_exit_4(tmp_path):
    d = _har(tmp_path, "http://127.0.0.1:9", [_entry("GET", "http://127.0.0.1:9/search?q=a")])
    assert sessionscan.main(["--errors", "--base", "http://127.0.0.1:9/", "--har", str(d)]) == 4


def test_probe_shapes():
    t = {"method": "GET", "path": "/p", "query": [("id", "1"), ("x", "2")], "json": False, "headers": {}}
    got = {name.split(" (")[0]: target for name, _, target, _, _ in sesserror.probes(t)}
    assert got["invalid type"] == "/p?id%5B%5D=1&x=2"
    assert got["missing parameters"] == "/p"
    assert got["invalid encoding"] == "/p?id=%ff%00&x=2"
    assert len(got["oversized value"]) > sesserror.OVERSIZE
