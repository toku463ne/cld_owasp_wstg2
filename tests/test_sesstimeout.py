"""Session timeout measurement (WSTG-SESS-07) against a loopback target, fake clock."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wstg import entrypoints as ep
from wstg import sessionscan, sesserror, sesstimeout

T0 = 1_800_000_000.0          # the capture's last request


class Clock:
    t = T0

    @classmethod
    def now(cls):
        return cls.t

    @classmethod
    def sleep(cls, s):
        cls.t += max(0.0, s)


class App(BaseHTTPRequestHandler):
    idle_limit = 12 * 60      # seconds
    abs_limit = 10 ** 9
    sessions: dict = {}       # value -> {"last": t, "born": t}
    hits = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        App.hits += 1
        ck = self.headers.get("Cookie", "")
        val = ck.split("SID=", 1)[1].split(";")[0] if "SID=" in ck else None
        s = App.sessions.get(val)
        ok = bool(s) and Clock.t - s["last"] <= App.idle_limit and Clock.t - s["born"] <= App.abs_limit
        if ok:
            s["last"] = Clock.t
            body = b"<h1>My page</h1>" + b"x" * 800
            self.send_response(200)
        else:
            body = b""
            self.send_response(302)
            self.send_header("Location", "/login")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def target(monkeypatch):
    Clock.t = T0
    App.sessions, App.hits = {}, 0
    monkeypatch.setattr(sesstimeout, "now", Clock.now)
    monkeypatch.setattr(sesstimeout, "sleep", Clock.sleep)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z")


def _capture(base, value, t_login, t_last):
    App.sessions[value] = {"last": t_last, "born": t_login}

    def e(method, path, t, cookie=True, set_cookie=None, post=None):
        req = {"method": method, "url": base + path, "headers": [],
               "cookies": [{"name": "SID", "value": value}] if cookie else []}
        if post:
            req["postData"] = {"mimeType": "application/x-www-form-urlencoded",
                               "params": [{"name": "user"}, {"name": "password"}]}
        rh = [{"name": "Set-Cookie", "value": set_cookie}] if set_cookie else []
        return {"startedDateTime": _iso(t), "request": req,
                "response": {"status": 200, "headers": rh, "content": {"size": 815}}}
    return [e("POST", "/login", t_login, cookie=False, post=True, set_cookie=f"SID={value}; Path=/; HttpOnly"),
            e("GET", "/mypage", t_last)]


def _dir(tmp_path, base, active=False):
    d = tmp_path / "har"
    d.mkdir()
    (d / "001-timeout-20260101-1200.har").write_text(json.dumps(
        {"log": {"entries": _capture(base, "idleSESSIONvalue01", T0 - 60, T0)}}))
    if active:
        (d / "002-timeout-active-20260101-1200.har").write_text(json.dumps(
            {"log": {"entries": _capture(base, "activeSESSIONvalue2", T0 - 60, T0)}}))
    return d


def _run(base, d, *extra):
    return sessionscan.main(["--timeout", "--base", base + "/", "--har", str(d), *extra])


def test_idle_timeout_bracketed(tmp_path, target, capsys):
    App.idle_limit = 12 * 60
    assert _run(target, _dir(tmp_path, target)) == 0
    out = capsys.readouterr().out
    assert "check after 0 min idle (since the capture): still accepted" in out
    assert "check after 10 min idle: still accepted" in out
    assert "check after 15 min idle: rejected" in out
    assert "idle timeout: between 10 min and 15 min (server-side) [OK]" in out
    assert "idleSESSIONvalue01" not in out
    assert "absolute timeout: not measured" in out


def test_no_idle_timeout_is_long(tmp_path, target, capsys):
    App.idle_limit = 10 ** 9
    assert _run(target, _dir(tmp_path, target), "--max-minutes", "400") == 0
    out = capsys.readouterr().out
    assert "idle timeout: none within 60 min idle (still accepted) [LONG]" in out


def test_absolute_timeout_with_active_session(tmp_path, target, capsys):
    App.idle_limit = 10 ** 9
    App.abs_limit = 90 * 60
    assert _run(target, _dir(tmp_path, target, active=True), "--idle-steps", "5", "--max-minutes", "240") == 0
    out = capsys.readouterr().out
    assert "keeping the 'timeout-active' session busy every 5" in out
    assert "absolute timeout: rejected after" in out
    App.abs_limit = 10 ** 9


def test_missing_timeout_capture_is_exit_3(tmp_path, target):
    d = tmp_path / "har"
    d.mkdir()
    assert _run(target, d) == 3


def test_other_checks_leave_the_timeout_captures_alone(tmp_path, target):
    d = _dir(tmp_path, target, active=True)
    assert sesserror.logged_in_hars(d) == []
    assert ep.read_har(ep.Inventory(target + "/"), d) == []
