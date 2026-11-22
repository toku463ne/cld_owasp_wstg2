"""Logout invalidation check (WSTG-SESS-06) against a loopback target."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wstg import entrypoints as ep
from wstg import session as se
from wstg import sessionscan, sesserror

OLD = "oldSESSIONvalue123456"


class App(BaseHTTPRequestHandler):
    invalidate = True
    seen: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        App.seen.append((self.path, self.headers.get("Cookie", "")))
        authed = f"PHPSESSID={OLD}" in self.headers.get("Cookie", "") and not App.invalidate
        if self.path.startswith("/account"):
            if authed:
                body = b"<h1>My account</h1>" + b"x" * 500
                self.send_response(200)
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                body = b""
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def app():
    App.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _e(method, url, *, cookie=None, status=200, set_cookie=None):
    req = {"method": method, "url": url, "headers": [],
           "cookies": [{"name": "PHPSESSID", "value": cookie}] if cookie else []}
    rh = [{"name": "Set-Cookie", "value": set_cookie}] if set_cookie else []
    return {"request": req, "response": {"status": status, "headers": rh, "content": {"size": 520}}}


def _logout_har(base, clear=True):
    return [
        _e("GET", f"{base}/login"),
        _e("POST", f"{base}/login", status=302, set_cookie=f"PHPSESSID={OLD}; Path=/; HttpOnly"),
        _e("GET", f"{base}/account", cookie=OLD),
        _e("GET", f"{base}/logout", cookie=OLD, status=302,
           set_cookie="PHPSESSID=deleted; Max-Age=0; Path=/" if clear else None),
        _e("GET", f"{base}/login"),
    ]


def _dir(tmp_path, entries, role="logout"):
    d = tmp_path / "har"
    d.mkdir(exist_ok=True)
    (d / f"001-{role}-20260101-1200.har").write_text(json.dumps({"log": {"entries": entries}}))
    return d


def test_logout_rejected_is_good(tmp_path, app, capsys):
    App.invalidate = True
    d = _dir(tmp_path, _logout_har(app))
    assert sessionscan.main(["--logout", "--base", app + "/", "--har", str(d)]) == 0
    out = capsys.readouterr().out
    assert "logout found in the 'logout' HAR by logout URL: GET /logout" in out
    assert "clears the cookie in the browser: yes" in out
    assert "rejected [GOOD]" in out
    assert "verdict: logout invalidates the session on the server" in out
    assert OLD not in out
    assert all("/logout" not in p for p, _ in App.seen)      # the logout itself is never replayed


def test_logout_still_accepted_is_fail(tmp_path, app, capsys):
    App.invalidate = False
    d = _dir(tmp_path, _logout_har(app, clear=False))
    assert sessionscan.main(["--logout", "--base", app + "/", "--har", str(d)]) == 0
    out = capsys.readouterr().out
    assert "clears the cookie in the browser: NO" in out
    assert "still accepted [FAIL]" in out
    assert "FAIL (the server still accepts the session after logout)" in out


def test_no_logout_capture_is_exit_3_with_a_diagnosis(tmp_path, app, capsys):
    d = _dir(tmp_path, _logout_har(app)[:3], role="user")
    assert sessionscan.main(["--logout", "--base", app + "/", "--har", str(d)]) == 3
    out = capsys.readouterr().out
    assert "no logout found" in out and "cookies sent: PHPSESSID" in out
    assert "GET /account -> 200" in out
    assert OLD not in out


@pytest.mark.parametrize("path", ["/index.php?action=logout", "/conta/sair", "/Account/LogOff",
                                  "/cerrar-sesion", "/api/auth/signout"])
def test_logout_url_variants(path):
    base = "https://www.example.com"
    e = _logout_har(base)
    e[3]["request"]["url"] = base + path
    e[3]["response"]["headers"] = []
    assert se.logout_index(e) == 3


def test_ensaio_is_not_a_logout():
    e = _logout_har("https://www.example.com")[:3]
    e.append(_e("GET", "https://www.example.com/ensaio", cookie=OLD))
    assert se.logout_index(e) is None


def test_custom_auth_cookie_and_cookie_change_fallback():
    base = "https://www.example.com"
    tok = "authVALUE987654321"

    def c(url, cookies, set_cookie=None):
        req = {"method": "GET", "url": url, "headers": [],
               "cookies": [{"name": n, "value": v} for n, v in cookies.items()]}
        rh = [{"name": "Set-Cookie", "value": set_cookie}] if set_cookie else []
        return {"request": req, "response": {"status": 200, "headers": rh}}
    entries = [
        c(f"{base}/", {"lang": "pt"}, set_cookie=f"MYAPP={tok}; Path=/; HttpOnly"),
        c(f"{base}/painel", {"lang": "pt", "MYAPP": tok}),
        c(f"{base}/x/7", {"lang": "pt", "MYAPP": tok}),           # an unrecognised logout URL
        c(f"{base}/", {"lang": "pt"}),
    ]
    assert "MYAPP" in se.session_names(entries)                  # HttpOnly makes it a session cookie
    assert se.logout_index(entries) is None                        # no URL, no clearing Set-Cookie
    i, how = se.logout_find(entries, "www.example.com", by_cookie_change=True)
    assert i == 2 and "stops being sent" in how


def test_logout_index_by_path_or_cleared_cookie():
    base = "https://www.example.com"
    assert se.logout_index(_logout_har(base)) == 3
    no_path = _logout_har(base)
    no_path[3]["request"]["url"] = f"{base}/bye"
    assert se.logout_index(no_path) == 3                       # found by the cleared cookie
    assert se.logout_index(_logout_har(base)[:3]) is None


def test_replay_tools_leave_out_the_logout_role(tmp_path):
    base = "https://www.example.com"
    d = _dir(tmp_path, _logout_har(base))
    (d / "002-storage-state-logout-20260101-1200.json").write_text(json.dumps({"cookies": [], "origins": []}))
    assert sesserror.logged_in_hars(d) == []
    assert ep.read_har(ep.Inventory(base + "/"), d) == []


def test_replay_tools_warn_about_a_capture_that_logs_out(tmp_path, capsys):
    base = "https://www.example.com"
    d = _dir(tmp_path, _logout_har(base), role="user")
    (d / "002-storage-state-user-20260101-1200.json").write_text(json.dumps({"cookies": [], "origins": []}))
    assert len(sesserror.logged_in_hars(d)) == 1
    assert "warning: the 'user' capture logs out" in capsys.readouterr().out
    inv = ep.Inventory(base + "/")
    assert len(ep.read_har(inv, d)) == 1
    assert any("logs out" in n for n in inv.notes)



def test_load_balancer_cookie_is_not_a_session_cookie():
    e = [{"request": {"method": "GET", "url": "https://www.example.com/", "cookies": []},
          "response": {"status": 200, "headers": [
              {"name": "Set-Cookie", "value": "AWSALB=abc; Path=/; HttpOnly"},
              {"name": "Set-Cookie", "value": "SESSIONID=xyz; Path=/; HttpOnly"}]}}]
    assert se.session_names(e) == {"SESSIONID"}
