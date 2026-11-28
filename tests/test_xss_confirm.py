"""Reflected XSS confirmation (WSTG-INPV-01 step 4): parse reflection-check, send a
standard sentinel payload, confirm execution in a (faked) headless browser."""
from __future__ import annotations

import argparse
import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from wstg import entrypoints as ep
from wstg import reflect


class App(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        App.seen.append(self.path)
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        v = q.get("q", "")
        if u.path == "/search":
            body = f"<p>Results for {v}</p>"                      # raw in HTML text -> executes
        elif u.path == "/safe":
            body = f"<p>Results for {html.escape(v)}</p>"         # encoded -> does not execute
        elif u.path == "/attr":
            body = f'<input value="{v.replace("<", "&lt;").replace(">", "&gt;")}">'   # < > encoded
        else:
            body = "<p>static</p>"
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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


def _reflect_stdout(tmp_path, app, capsys) -> str:
    kat = tmp_path / "katana"
    kat.mkdir()
    (kat / "katana.txt").write_text("\n".join(f"{app}{p}" for p in [
        "/search?q=a", "/safe?q=a", "/attr?q=a"]) + "\n")
    assert reflect.main(["--base", app + "/", "--katana", str(kat)]) == 0
    return capsys.readouterr().out


def _fake_render(url, state, out_png, proxy, timeout_ms=15000):
    """Fetch the url and treat a raw, unescaped sentinel <script> in the body as executed,
    standing in for a real browser running it."""
    import re as _re
    a = ep.fetch(url, "")
    m = _re.search(r"<script>window\.__WSTG_XSS=('|\")(WSTGXSS[0-9a-f]+)\1</script>", a.body or "")
    if out_png:
        out_png.write_bytes(b"\x89PNG\r\n\x1a\n")
    return {"value": m.group(2) if m else "", "status": a.status, "errors": [], "error": "",
            "final_url": url, "redirected": False}


# ---- unit: payloads, parsing, url building -----------------------------------------

def test_sentinel_payload_per_context():
    assert reflect.sentinel_payload("html", "", "T") == "<script>window.__WSTG_XSS='T'</script>"
    assert reflect.sentinel_payload("attribute", '"', "T") == "\"><script>window.__WSTG_XSS='T'</script>"
    assert reflect.sentinel_payload("attribute", "u", "T") == "><script>window.__WSTG_XSS='T'</script>"
    assert reflect.sentinel_payload("script", "'", "T") == "';window.__WSTG_XSS='T';//"
    assert reflect.sentinel_payload("script", "", "T") == ";window.__WSTG_XSS='T';//"


def test_parse_unencoded_handles_parens_in_where_label(tmp_path, app, capsys):
    out = _reflect_stdout(tmp_path, app, capsys)
    items = reflect.parse_unencoded(out)
    by = {it["param"]: it for it in items}
    # /search (html) and /attr ("-quoted) are REFLECTED-UNENCODED; /safe is encoded.
    assert set(i["param"] for i in items) == {"q"} and len(items) == 2
    ctxs = sorted((it["context"], it["delim"]) for it in items)
    assert ("attribute", '"') in ctxs and ("html", "") in ctxs
    assert all(it["url"].startswith(app) for it in items)


def test_confirm_url_replaces_only_the_named_parameter():
    it = {"url": "http://h/s?q=wstg1<\"'>&page=2", "param": "q", "context": "html", "delim": ""}
    url = reflect.confirm_url(it, "T")
    sp = urlsplit(url)
    q = parse_qs(sp.query, keep_blank_values=True)
    assert q["page"] == ["2"] and "<script>window.__WSTG_XSS='T'</script>" in q["q"][0]


# ---- run_confirm -------------------------------------------------------------------

def _args(reflect_dir, app, **kw):
    ns = argparse.Namespace(base=app + "/", reflect=str(reflect_dir), har=None, out=None,
                            list=False, request=[], all=False, proxy="", pause=0, stop_file=None, agree=False)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def test_list_sends_nothing(tmp_path, app, capsys):
    rd = tmp_path / "rc"
    rd.mkdir()
    (rd / "stdout.txt").write_text(_reflect_stdout(tmp_path, app, capsys))
    App.seen = []
    assert reflect.run_confirm(_args(rd, app, list=True), render=_fake_render) == 0
    out = capsys.readouterr().out
    assert "REFLECTED-UNENCODED parameter(s) from reflection-check" in out
    assert App.seen == []                                    # --list makes no request


def test_agree_required(tmp_path, app, capsys):
    rd = tmp_path / "rc"
    rd.mkdir()
    (rd / "stdout.txt").write_text(_reflect_stdout(tmp_path, app, capsys))
    assert reflect.run_confirm(_args(rd, app, all=True, agree=False), render=_fake_render) == 2
    assert "pass --agree" in capsys.readouterr().err


def test_all_confirms_execution(tmp_path, app, capsys):
    rd = tmp_path / "rc"
    rd.mkdir()
    (rd / "stdout.txt").write_text(_reflect_stdout(tmp_path, app, capsys))
    out_dir = tmp_path / "shots"
    r = reflect.run_confirm(_args(rd, app, all=True, agree=True, out=str(out_dir)), render=_fake_render)
    assert r == 0
    out = capsys.readouterr().out
    # /search (html text) executes; /attr ("-quoted, < > encoded by the app) does not.
    assert "CONFIRMED-EXECUTED" in out and "NOT EXECUTED" in out
    assert "verdict: 1/2 executed" in out
    assert list(out_dir.glob("xss-*.png"))                   # a screenshot per parameter


def test_stop_file_halts(tmp_path, app, capsys):
    rd = tmp_path / "rc"
    rd.mkdir()
    (rd / "stdout.txt").write_text(_reflect_stdout(tmp_path, app, capsys))
    stop = tmp_path / "stop"
    stop.write_text("x")
    assert reflect.run_confirm(_args(rd, app, all=True, agree=True, stop_file=str(stop)),
                               render=_fake_render) == 0
    assert "stopped: 0/" in capsys.readouterr().out


def test_log_shows_final_url_and_redirect(tmp_path, app, capsys):
    rd = tmp_path / "rc"
    rd.mkdir()
    (rd / "stdout.txt").write_text(_reflect_stdout(tmp_path, app, capsys))

    def redir_render(url, state, out_png, proxy, timeout_ms=15000):
        return {"value": "", "status": 302, "errors": [], "error": "",
                "final_url": "http://err.example.test/?aspxerrorpath=/x", "redirected": True}

    assert reflect.run_confirm(_args(rd, app, all=True, agree=True), render=redir_render) == 0
    out = capsys.readouterr().out
    assert "final url: http://err.example.test/?aspxerrorpath=/x  [redirected]" in out
    assert "NOT EXECUTED (HTTP 302)" in out
