"""Response-timing side-channel measurement (WSTG-BUSL-04 step 1) against a loopback app."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from wstg import timing


# ---- unit: statistics -------------------------------------------------------------


def test_mann_whitney_separates_and_overlaps():
    a = [10.0, 11, 12, 13, 14, 15]
    far = [100.0, 101, 102, 103, 104, 105]
    same = [10.5, 11.5, 12.5, 13.5, 14.5, 15.5]
    assert timing.mann_whitney_p(a, far) < 0.01
    assert timing.mann_whitney_p(a, same) > 0.05
    assert timing.mann_whitney_p([1.0, 2], [3.0, 4]) is None       # too few points


def test_quartiles():
    q1, q3 = timing._quartiles([1, 2, 3, 4, 5])
    assert q1 == 2 and q3 == 4


# ---- integration: a loopback app that delays one class ----------------------------


class App(BaseHTTPRequestHandler):
    slow_value = "valid"       # requests whose "u" equals this are delayed
    delay = 0.03

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        if q.get("u", [""])[0] == App.slow_value:
            time.sleep(App.delay)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def app():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _args(base, **kw):
    ns = {"base": base, "url": base + "/check", "method": "GET", "param": "u",
          "value_a": "valid", "value_b": "absent", "fixed": None, "body": False,
          "har": None, "samples": 15, "warmup": 2, "pause": 0}
    ns.update(kw)
    return type("A", (), ns)


def test_detects_a_timing_difference(app, capsys):
    App.slow_value, App.delay = "valid", 0.04
    assert timing.run(_args(app)) == 0
    out = capsys.readouterr().out
    assert "class A: n=" in out and "class B: n=" in out
    assert "DISTINGUISHABLE" in out
    assert "race (double-apply) half of BUSL-04 stays manual" in out


def test_reports_no_difference_when_timing_is_uniform(app, capsys):
    App.slow_value, App.delay = "__none__", 0.0      # neither class is delayed
    assert timing.run(_args(app)) == 0
    out = capsys.readouterr().out
    assert "NOT-DISTINGUISHABLE" in out


def test_flags_a_status_oracle(app, capsys):
    # A different response status for one class is a direct oracle, reported before timing.
    class Status(App):
        def do_GET(self):
            q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            code = 200 if q.get("u", [""])[0] == "valid" else 404
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Status)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert timing.run(_args(base)) == 0
    finally:
        srv.shutdown()
    assert "STATUS-DIFFERS" in capsys.readouterr().out


def test_values_are_not_printed(app, capsys):
    assert timing.run(_args(app, value_a="secret-user", value_b="other-user")) == 0
    out = capsys.readouterr().out
    assert "secret-user" not in out and "other-user" not in out
    assert "chars" in out       # masked as a length


def test_exit_4_when_nothing_answers(capsys):
    # Nothing is listening on this port.
    rc = timing.run(_args("http://127.0.0.1:1", samples=3, warmup=0))
    assert rc == 4
