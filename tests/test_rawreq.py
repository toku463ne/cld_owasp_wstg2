"""Raw/malformed request probe (WSTG-INPV-16 step 2) against loopback apps."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wstg import rawreq


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, code):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self._reply(self.code_for(self.path))

    def code_for(self, path):
        return 200


def _katana(tmp_path, base, *paths):
    kat = tmp_path / "katana"
    kat.mkdir()
    (kat / "katana.txt").write_text("".join(f"{base}{p}\n" for p in paths))
    return str(kat)


# ---- unit tests --------------------------------------------------------------------

def test_variants_are_distinct_and_change_the_path():
    vs = rawreq.variants("/admin")
    paths = [v for _, v in vs]
    assert "/admin" not in paths and len(paths) == len(set(paths))
    assert any(p == "/ADMIN" for p in paths) and any("%2f" in p for p in paths)


def test_candidates_dedup_and_normalise():
    cs = rawreq.candidates("http://x/", None, ["/admin", "admin", "/x"])
    assert cs == ["/admin", "/x"]


# ---- normalisation bypass ----------------------------------------------------------

def test_normalize_bypass_detected(tmp_path, capsys):
    class App(_Base):
        def code_for(self, path):
            if path == "/admin":
                return 403                       # the front end blocks the canonical path
            return 200 if "admin" in path.lower() else 404   # a naive back end reaches it
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert rawreq.main(["--base", base + "/", "--path", "/admin", "--request", "1", "--agree"]) == 0
        out = capsys.readouterr().out
        assert "SUSPECTED-bypass" in out
    finally:
        srv.shutdown()


def test_normalize_all_blocked_is_clean(tmp_path, capsys):
    class App(_Base):
        def code_for(self, path):
            return 403 if "admin" in path.lower() else 404   # blocked canonical and variants
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert rawreq.main(["--base", base + "/", "--path", "/admin", "--request", "1", "--agree"]) == 0
        out = capsys.readouterr().out
        assert "blocked" in out and "SUSPECTED-bypass" not in out
    finally:
        srv.shutdown()


def test_normalize_open_path_has_nothing_to_bypass(tmp_path, capsys):
    class App(_Base):
        def code_for(self, path):
            return 200                           # canonical not blocked
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert rawreq.main(["--base", base + "/", "--path", "/admin", "--request", "1", "--agree"]) == 0
        out = capsys.readouterr().out
        assert "not blocked, nothing to bypass" in out and "SUSPECTED-bypass" not in out
    finally:
        srv.shutdown()


# ---- parser battery ----------------------------------------------------------------

def test_parser_battery_runs(tmp_path, capsys):
    srv = _serve(_Base)                          # always 200
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        # item 1 is the parser battery when there is no candidate path
        assert rawreq.main(["--base", base + "/", "--request", "1", "--agree"]) == 0
        out = capsys.readouterr().out
        assert "parser battery" in out and "duplicate-host" in out and "unknown-method" in out
        assert "oversized-header" in out and "needs --agree-oversized" in out
    finally:
        srv.shutdown()


def test_oversized_runs_only_when_opted_in(tmp_path, capsys):
    class App(_Base):
        def code_for(self, path):
            return 200
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert rawreq.main(["--base", base + "/", "--request", "1", "--agree", "--agree-oversized"]) == 0
        out = capsys.readouterr().out
        assert "oversized-header" in out and "needs --agree-oversized" not in out
    finally:
        srv.shutdown()


# ---- guards ------------------------------------------------------------------------

def test_agree_required(tmp_path, capsys):
    srv = _serve(_Base)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert rawreq.main(["--base", base + "/", "--all"]) == 2
        assert "pass --agree" in capsys.readouterr().err
    finally:
        srv.shutdown()


def test_list_sends_nothing(tmp_path, capsys):
    base = "http://127.0.0.1:9"
    kat = _katana(tmp_path, base, "/admin?x=1", "/login")
    assert rawreq.main(["--base", base + "/", "--katana", kat, "--list"]) == 0
    out = capsys.readouterr().out
    assert "/admin" in out and "parser battery" in out
