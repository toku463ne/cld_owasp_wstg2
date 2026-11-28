"""Injection probe engine (WSTG-INPV active-probe steps) against loopback apps."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from wstg import inject


class SqliApp(BaseHTTPRequestHandler):
    """A toy app vulnerable to SQLi in ?id: error on a quote, boolean on OR/AND, sleep."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        v = q.get("id", "")
        rows = "<li>Alice</li><li>Bob</li><li>Carol</li>"
        if u.path == "/items":
            low = v.lower()
            if "sleep(5)" in low or "pg_sleep(5)" in low or "waitfor delay" in low:
                time.sleep(5.2)
                body = f"<ul>{rows}</ul>"
            elif v.endswith("'") or v.endswith('"') or v.endswith("')") or v.endswith(";") or v.endswith("\\"):
                body = "<h1>SQL syntax error near ''</h1>You have an error in your SQL syntax"
            elif "or '1'='1" in low or "or 1=1" in low:
                body = f"<ul>{rows}</ul>"                                   # TRUE: all rows
            elif "and '1'='2" in low or "and 1=2" in low:
                body = "<ul></ul>"                                         # FALSE: no rows
            else:
                body = f"<ul>{rows}</ul>"
        else:
            body = "<p>static</p>"
        self._send(body)

    def _send(self, body):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


class SstiApp(BaseHTTPRequestHandler):
    """Reflects ?name; evaluates a ${...} / {{...}} arithmetic expression."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        import re
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        v = q.get("name", "")
        m = re.search(r"(?:\$\{+|\{\{|#\{|<%=|\{)\s*7\*191\s*(?:\}+|%>)", v)
        shown = "1337" if m else v                                        # evaluate the expression
        b = f"<p>Hello {shown}</p>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def sqli():
    srv = _serve(SqliApp)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def ssti():
    srv = _serve(SstiApp)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _katana(tmp_path, base, path):
    kat = tmp_path / "katana"
    kat.mkdir()
    (kat / "katana.txt").write_text(f"{base}{path}\n")
    return str(kat)


def test_sqli_error_and_boolean_detected(tmp_path, sqli, capsys):
    kat = _katana(tmp_path, sqli, "/items?id=5")
    r = inject.main(["--pack", "sqli", "--base", sqli + "/", "--katana", kat, "--all", "--agree"])
    assert r == 0
    out = capsys.readouterr().out
    assert "SUSPECTED-error" in out                      # the quote raises a SQL error first
    assert "verdict: 1 parameter(s) SUSPECTED by sqli" in out


def test_sqli_boolean_without_error(tmp_path, capsys):
    """An app that does not error on a quote but diverges on TRUE/FALSE -> boolean hit."""
    class BoolApp(SqliApp):
        def do_GET(self):
            u = urlsplit(self.path)
            v = {k: x[0] for k, x in parse_qs(u.query, keep_blank_values=True).items()}.get("id", "").lower()
            rows = "<li>Alice</li><li>Bob</li><li>Carol</li>" * 3
            if "and '1'='2" in v or "and 1=2" in v:
                self._send("<ul></ul>")
            else:
                self._send(f"<ul>{rows}</ul>")
    srv = _serve(BoolApp)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        kat = _katana(tmp_path, base, "/items?id=5")
        assert inject.main(["--pack", "sqli", "--base", base + "/", "--katana", kat, "--all", "--agree"]) == 0
        assert "SUSPECTED-boolean" in capsys.readouterr().out
    finally:
        srv.shutdown()


@pytest.mark.slow
def test_sqli_time_based(tmp_path, capsys):
    """An app that only sleeps (no error, no boolean divergence) -> time hit."""
    class TimeApp(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            v = {k: x[0] for k, x in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}.get("id", "")
            if "sleep(5)" in v.lower() or "pg_sleep(5)" in v.lower() or "waitfor delay" in v.lower():
                time.sleep(5.2)
            b = b"<ul><li>row</li></ul>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = _serve(TimeApp)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        kat = _katana(tmp_path, base, "/items?id=5")
        assert inject.main(["--pack", "sqli", "--base", base + "/", "--katana", kat, "--all", "--agree"]) == 0
        assert "SUSPECTED-time" in capsys.readouterr().out
    finally:
        srv.shutdown()


def test_ssti_eval_detected(tmp_path, ssti, capsys):
    kat = _katana(tmp_path, ssti, "/hello?name=x")
    assert inject.main(["--pack", "ssti", "--base", ssti + "/", "--katana", kat, "--all", "--agree"]) == 0
    out = capsys.readouterr().out
    assert "SUSPECTED-eval" in out and "1337" in out


def test_clean_app_reports_clean(tmp_path, capsys):
    class SafeApp(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            import html
            v = {k: x[0] for k, x in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}.get("id", "")
            b = f"<p>{html.escape(v)}</p>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = _serve(SafeApp)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        kat = _katana(tmp_path, base, "/items?id=5")
        assert inject.main(["--pack", "sqli", "--base", base + "/", "--katana", kat, "--all", "--agree"]) == 0
        out = capsys.readouterr().out
        assert "=> clean" in out and "=> SUSPECTED" not in out
        assert "verdict: 0 parameter(s) SUSPECTED" in out
    finally:
        srv.shutdown()


def test_list_sends_nothing(tmp_path, sqli, capsys):
    kat = _katana(tmp_path, sqli, "/items?id=5")
    assert inject.main(["--pack", "sqli", "--base", sqli + "/", "--katana", kat, "--list"]) == 0
    out = capsys.readouterr().out
    assert "?id" in out and "/items" in out


def test_agree_required(tmp_path, sqli, capsys):
    kat = _katana(tmp_path, sqli, "/items?id=5")
    assert inject.main(["--pack", "sqli", "--base", sqli + "/", "--katana", kat, "--all"]) == 2
    assert "pass --agree" in capsys.readouterr().err


def test_unknown_pack(capsys):
    assert inject.main(["--pack", "nope", "--base", "http://127.0.0.1/"]) == 2
    assert "unknown pack" in capsys.readouterr().err


class _ErrApp(BaseHTTPRequestHandler):
    """Echoes a given engine error when the value ends with a metacharacter."""
    trigger = ("'",)
    error = "error"

    def log_message(self, *a):
        pass

    def do_GET(self):
        v = {k: x[0] for k, x in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}.get("id", "")
        body = self.error if any(v.endswith(t) for t in self.trigger) else "<p>ok</p>"
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def test_xpath_error_detected(tmp_path, capsys):
    class App(_ErrApp):
        trigger = ("'", "]", ")")
        error = "<p>org.apache.xpath.XPathException: unexpected token</p>"
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        kat = _katana(tmp_path, base, "/q?id=5")
        assert inject.main(["--pack", "xpath", "--base", base + "/", "--katana", kat, "--all", "--agree"]) == 0
        assert "SUSPECTED-error" in capsys.readouterr().out
    finally:
        srv.shutdown()


def test_ldap_error_detected(tmp_path, capsys):
    class App(_ErrApp):
        trigger = (")", "(", "*)(")
        error = "<p>javax.naming.directory.InvalidSearchFilterException</p>"
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        kat = _katana(tmp_path, base, "/q?id=5")
        assert inject.main(["--pack", "ldap", "--base", base + "/", "--katana", kat, "--all", "--agree"]) == 0
        assert "SUSPECTED-error" in capsys.readouterr().out
    finally:
        srv.shutdown()


@pytest.mark.slow
def test_cmd_time_based(tmp_path, capsys):
    class App(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            v = {k: x[0] for k, x in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}.get("id", "")
            if "sleep 5" in v or "timeout /t 5" in v or "ping -c 5" in v:
                time.sleep(5.2)
            b = b"<p>done</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        kat = _katana(tmp_path, base, "/run?id=x")
        assert inject.main(["--pack", "cmd", "--base", base + "/", "--katana", kat, "--all", "--agree"]) == 0
        assert "SUSPECTED-time" in capsys.readouterr().out
    finally:
        srv.shutdown()
