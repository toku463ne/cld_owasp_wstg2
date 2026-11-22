"""Output-encoding check of reflected parameters (WSTG-INPV-01) against a loopback app."""
from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from wstg import har, reflect


class App(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        App.seen.append(self.path)
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        v = q.get("q", "")
        ctype = "text/html; charset=utf-8"
        if u.path == "/search":
            body = f"<p>Results for {v}</p>"                           # raw in HTML text
        elif u.path == "/safe":
            body = f"<p>Results for {html.escape(v)}</p>"
        elif u.path == "/attr":
            body = f'<input value="{v.replace("<", "&lt;").replace(">", "&gt;")}">'   # quotes raw
        elif u.path == "/js":
            body = f"<script>var s = '{v}';</script>"
        elif u.path == "/api":
            body, ctype = json.dumps({"q": v}, ensure_ascii=False).replace("\\\"", '"'), "application/json"
        else:
            body = "<p>static</p>"
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


@pytest.fixture
def app():
    App.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_marker_check_tells_unencoded_from_encoded(tmp_path, app, capsys):
    kat = tmp_path / "katana"
    kat.mkdir()
    (kat / "katana.txt").write_text("\n".join(f"{app}{p}" for p in [
        "/search?q=a", "/search?q=b", "/safe?q=a", "/attr?q=a", "/js?q=a", "/api?q=a", "/none?q=a",
        "/logout?next=/", "/app.js?v=1"]) + "\nhttps://cdn.example.com/x?q=1\n")
    assert reflect.main(["--base", app + "/", "--katana", str(kat)]) == 0
    out = capsys.readouterr().out
    assert "/search ?q: REFLECTED-UNENCODED" in out and "html: raw <" in out
    assert "/safe ?q: reflected, encoded" in out
    assert "/attr ?q: REFLECTED-UNENCODED" in out and "attribute: raw" in out
    assert "/js ?q: REFLECTED-UNENCODED" in out and "script: raw" in out
    assert "/api ?q: reflected raw in a non-HTML response" in out
    assert "not reflected: 1 parameter(s)" in out
    assert "verdict: 3 parameter(s) REFLECTED-UNENCODED" in out
    assert not any(p.startswith(("/logout", "/app.js")) for p in App.seen)
    assert sum(1 for p in App.seen if p.startswith("/search")) == 1      # same template probed once
    assert not any("script" in p.lower() or "alert" in p.lower() for p in App.seen)   # no attack payload


def test_no_parameter_found(tmp_path, app, capsys):
    assert reflect.main(["--base", app + "/"]) == 0
    assert "no GET parameter found" in capsys.readouterr().out


@pytest.mark.parametrize("body,ctx,raw", [
    ("<p>WORD<\"'></p>", "html", ["<"]),
    ("<p>WORD&lt;&quot;&#39;&gt;</p>", "html", []),
    ('<a title="WORD&lt;&quot;&#39;&gt;">', "attribute", []),
    ('<a title="WORD&lt;"\'&gt;">', "attribute", ['"', "'"]),
    ("<script>x='WORD<\\\"\\'>'</script>", "script", ["<"]),
])
def test_classify_contexts(body, ctx, raw):
    occ = reflect.classify(body, "WORD")
    assert occ[0][0] == ctx and reflect.risky(*occ[0]) == raw


def test_xss_headers_view(tmp_path, capsys):
    def page(csp=None, nosniff=False):
        h = [{"name": "Content-Type", "value": "text/html"}]
        if csp:
            h.append({"name": "Content-Security-Policy", "value": csp})
        if nosniff:
            h.append({"name": "X-Content-Type-Options", "value": "nosniff"})
        return {"request": {"method": "GET", "url": "https://app.example.com/p", "headers": [], "cookies": []},
                "response": {"status": 200, "headers": h, "content": {"text": ""}}}
    f = tmp_path / "001-user.har"
    f.write_text(json.dumps({"log": {"entries": [
        page(), page("default-src 'self'; script-src 'self' 'unsafe-inline'", True),
        page("default-src 'self'", True)]}}))
    har.main(["xss-headers", str(f)])
    out = capsys.readouterr().out
    assert "missing on 1, weak on 1, blocks inline script on 1" in out
    assert "WEAK: 'unsafe-inline'" in out
    assert "nosniff: missing on 1" in out and "charset in Content-Type: missing on 3" in out


# -- stored view (WSTG-INPV-02): markers saved during the capture, read from the HAR only --

def _e(method, path, *, body="", ctype="text/html", sent=None):
    req = {"method": method, "url": f"https://app.example.com{path}", "headers": [], "cookies": []}
    if sent:
        req["postData"] = {"mimeType": "application/x-www-form-urlencoded",
                           "params": [{"name": k, "value": v} for k, v in sent.items()]}
    return {"request": req, "response": {"status": 200, "headers": [{"name": "Content-Type", "value": ctype}],
                                          "content": {"text": body}}}


def test_stored_view_finds_where_markers_are_shown(tmp_path, capsys):
    user = tmp_path / "001-user.har"
    user.write_text(json.dumps({"log": {"entries": [
        _e("POST", "/profile", sent={"name": "wstg01<\"'>", "csrf": "tok"}),
        _e("GET", "/profile", body='<input value="wstg01&lt;&quot;&#39;&gt;">'),
        _e("POST", "/comments", sent={"text": "wstg02<\"'>"}),
        _e("GET", "/posts/12", body="<p>wstg02<\"'></p>"),
        _e("POST", "/notes", sent={"text": "wstg03<\"'>"}),
    ]}}))
    admin = tmp_path / "002-admin.har"
    admin.write_text(json.dumps({"log": {"entries": [
        _e("GET", "/admin/users", body="<td>wstg01<\"'></td>"),
    ]}}))
    har.main(["stored", str(user), str(admin)])
    out = capsys.readouterr().out
    assert "wstg01, wstg02, wstg03" in out
    assert "[wstg01] saved by user: POST /profile" in out
    assert "GET /profile -> 200: encoded (attribute)" in out
    assert "GET /admin/users -> 200 (shown to admin): STORED-UNENCODED (html: raw <)" in out
    assert "GET /posts/<id> -> 200: STORED-UNENCODED" in out
    assert "[wstg03]" in out and "not displayed in any captured response" in out
    assert "verdict: 2 display(s) STORED-UNENCODED" in out
    assert "tok" not in out


def test_stored_view_without_marker(tmp_path, capsys):
    f = tmp_path / "001-user.har"
    f.write_text(json.dumps({"log": {"entries": [_e("GET", "/", body="<p>hi</p>")]}}))
    har.main(["stored", str(f)])
    assert "type a marker such as wstg01" in capsys.readouterr().out


def test_reports_location_header_reflection(tmp_path, app, capsys):
    # /redir echoes the marker into the Location header (open-redirect / splitting candidate).
    class R(App):
        def do_GET(self2):
            from urllib.parse import urlsplit, parse_qs
            u = urlsplit(self2.path)
            if u.path == "/redir":
                v = parse_qs(u.query, keep_blank_values=True).get("url", [""])[0]
                self2.send_response(302)
                self2.send_header("Location", v)
                self2.send_header("Content-Length", "0")
                self2.end_headers()
                return
            App.do_GET(self2)
    srv = __import__("http.server", fromlist=["ThreadingHTTPServer"]).ThreadingHTTPServer(("127.0.0.1", 0), R)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    kat = tmp_path / "k"
    kat.mkdir()
    (kat / "katana.txt").write_text(f"{base}/redir?url=/home\n{base}/search?q=a\n")
    try:
        assert reflect.main(["--base", base + "/", "--katana", str(kat)]) == 0
    finally:
        srv.shutdown()
    out = capsys.readouterr().out
    assert "/redir ?url: HEADER-REFLECTED into Location" in out
    assert "1 reflected into the Location header" in out


def test_hpp_reports_precedence_rule(tmp_path, capsys):
    # /last echoes the last value (parse_qs[-1]); /first the first; /both joins them.
    class H(App):
        def do_GET(self2):
            from urllib.parse import urlsplit, parse_qs
            u = urlsplit(self2.path)
            vals = parse_qs(u.query, keep_blank_values=True).get("id", [""])
            if u.path == "/last":
                body = f"<p>{vals[-1]}</p>"
            elif u.path == "/first":
                body = f"<p>{vals[0]}</p>"
            elif u.path == "/both":
                body = f"<p>{','.join(vals)}</p>"
            else:
                body = "<p>static</p>"
            b = body.encode()
            self2.send_response(200)
            self2.send_header("Content-Type", "text/html")
            self2.send_header("Content-Length", str(len(b)))
            self2.end_headers()
            self2.wfile.write(b)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    kat = tmp_path / "k"
    kat.mkdir()
    (kat / "katana.txt").write_text("\n".join(f"{base}{p}?id=1" for p in ["/last", "/first", "/both", "/none"]) + "\n")
    try:
        assert reflect.main(["--base", base + "/", "--hpp", "--katana", str(kat)]) == 0
    finally:
        srv.shutdown()
    out = capsys.readouterr().out
    assert "/last ?id: last value wins" in out
    assert "/first ?id: first value wins" in out
    assert "/both ?id: both values used" in out
    assert "/none ?id: neither reflected" in out
    assert "1 first value wins" in out and "1 last value wins" in out
