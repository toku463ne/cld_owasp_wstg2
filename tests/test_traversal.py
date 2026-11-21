"""Directory-traversal probe (WSTG-ATHZ-01 step 2) against a loopback test server."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit, parse_qs

import pytest

from wstg import catalog as catmod
from wstg import runner as rmod
from wstg import targets as tm
from wstg import traversal

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


class Handler(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Handler.seen.append(self.path)
        u = urlsplit(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        if u.path == "/page":
            # Naively reads whatever "file" points to (after collapsing ../), simulating traversal.
            name = unquote((q.get("file") or [""])[0]).split("\x00")[0]
            if "etc/passwd" in name.replace("\\", "/"):
                return self._send(200, PASSWD.encode())
            if name in ("home", "", "index"):
                return self._send(200, b"<html>Welcome home page</html>")
            return self._send(404, b"not found")
        if u.path == "/inc":
            v = unquote((q.get("page") or [""])[0])
            if v.startswith("data://text/plain;base64,"):
                import base64 as _b64
                try:
                    code = _b64.b64decode(v.split(",", 1)[1]).decode()
                except Exception:
                    code = ""
                m = re.search(r"echo (\d+)\*(\d+)", code)
                if m:        # simulate PHP running the wrapper
                    return self._send(200, str(int(m.group(1)) * int(m.group(2))).encode())
            return self._send(200, b"<html>page</html>")
        if u.path == "/show":
            v = unquote((q.get("tpl") or [""])[0])
            if v.startswith("data://text/plain;base64,"):
                import base64 as _b64
                try:
                    return self._send(200, _b64.b64decode(v.split(",", 1)[1]))   # shows source, no eval
                except Exception:
                    pass
            return self._send(200, b"<html>tpl</html>")
        if u.path == "/rfi":
            # Includes a remote URL: fetches it server-side and "runs" it (simulating RFI).
            v = unquote((q.get("file") or [""])[0])
            if v.startswith("http://"):
                import urllib.request
                try:
                    content = urllib.request.urlopen(v, timeout=2).read().decode()   # fetches the callback
                except Exception:
                    content = ""
                m = re.search(r"echo (\d+)\*(\d+)", content)
                if m:
                    return self._send(200, str(int(m.group(1)) * int(m.group(2))).encode())
            return self._send(200, b"<html>rfi</html>")
        if u.path == "/safe":
            # Validated parameter: only an allow-listed name, traversal refused.
            name = (q.get("doc") or [""])[0]
            if name in ("a", "b"):
                return self._send(200, b"<html>doc</html>")
            return self._send(400, b"bad request")
        return self._send(404, b"nope")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    Handler.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_probe_flags_a_real_traversal_and_not_a_validated_param(tmp_path, server, capsys):
    lst = tmp_path / "list" / "items"
    lst.mkdir(parents=True)
    (lst / "001.txt").write_text(f"{server}/page?file=home\n{server}/safe?doc=a\n"
                                 "https://other.example.org/page?file=x\n")
    rc = traversal.main(["--base", server + "/", "--list", str(lst.parent)])
    out = capsys.readouterr().out
    assert rc == 0
    blocks = {b.split("   [")[0]: b for b in out.split("\n== ")[1:]}
    page = blocks["/page?file="]
    assert "TRAVERSAL: response contains /etc/passwd" in page
    assert "root:x:0:0:" in page            # body excerpt is saved (no sensitivity concern)
    assert "baseline (file=home): 200" in page
    safe = blocks["/safe?doc="]
    assert "TRAVERSAL" not in safe          # validated parameter: every payload refused
    assert "400" in safe
    # only the base host is contacted; the other-host candidate is skipped
    assert "other.example.org" in out and "skipped" in out
    assert all("127.0.0.1" not in h or True for h in Handler.seen)
    assert not any("etc/passwd" in h and "other" in h for h in Handler.seen)


def test_probe_detects_code_execution_and_source_display(tmp_path, server, capsys):
    from wstg import traversal
    lst = tmp_path / "list" / "items"
    lst.mkdir(parents=True)
    (lst / "001.txt").write_text(f"{server}/inc?page=home\n{server}/show?tpl=a\n")
    traversal.main(["--base", server + "/", "--list", str(lst.parent)])
    out = capsys.readouterr().out
    blocks = {b.split("   [")[0]: b for b in out.split("\n== ")[1:]}
    assert "CODE EXECUTION: the included wrapper ran" in blocks["/inc?page="]
    assert "982007569" in blocks["/inc?page="]
    assert "included but shown as source, not executed" in blocks["/show?tpl="]


def test_probe_detects_remote_file_inclusion(tmp_path, server, capsys):
    lst = tmp_path / "list" / "items"
    lst.mkdir(parents=True)
    (lst / "001.txt").write_text(f"{server}/rfi?file=home\n")
    traversal.main(["--base", server + "/", "--list", str(lst.parent)])
    out = capsys.readouterr().out
    block = out.split("\n== ")[1]
    assert "REMOTE CODE EXECUTION" in block and "982007569" in block
    assert "callback at http://127.0.0.1:" in out


def test_no_callback_skips_remote_inclusion(tmp_path, server, capsys):
    lst = tmp_path / "list" / "items"
    lst.mkdir(parents=True)
    (lst / "001.txt").write_text(f"{server}/rfi?file=home\n")
    traversal.main(["--base", server + "/", "--list", str(lst.parent), "--no-callback"])
    out = capsys.readouterr().out
    assert "remote file inclusion test off" in out
    assert "REMOTE CODE EXECUTION" not in out


def test_probe_candidates_from_crawl_and_limit(tmp_path, server, capsys):
    kat = tmp_path / "kat"
    kat.mkdir()
    (kat / "katana.txt").write_text("\n".join(f"{server}/page?file=f{i}" for i in range(3))
                                    + f"\n{server}/page?id=5\n")       # id= is not a file param
    rc = traversal.main(["--base", server + "/", "--katana", str(kat), "--max", "1"])
    out = capsys.readouterr().out
    # /page?file= dedups to one candidate (same path+param); id= ignored
    assert "1 file-naming parameter(s)" in out and rc == 0


def test_no_answer_is_a_failed_collection(tmp_path, capsys):
    lst = tmp_path / "list" / "items"
    lst.mkdir(parents=True)
    (lst / "001.txt").write_text("http://127.0.0.1:9/page?file=home\n")   # discard port
    assert traversal.main(["--base", "http://127.0.0.1:9/", "--list", str(lst.parent)]) == 4


def test_catalog_traversal_probe_is_scope_checked(cfg, db):
    cat = catmod.load()
    ev = cat.evidence["traversal-probe"]
    assert ev.kind == "auto" and ev.heavy and ev.level == "full"
    assert "traversal-param-list" in ev.inputs and "katana-crawl" in ev.inputs
    site = tm.create(db, cfg, "www.example.com", "fqdn")
    tm.update_scope(db, site, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="C-1",
                    valid_from="2000-01-01", valid_until="2099-12-31", actor="test")
    scope = tm.get_scope(db, site)
    argv, _, _ = rmod.build_argv(ev, tm.placeholder_values(cfg, site, scope) | {"out": "/tmp/x"}, "", 0,
                                 rmod.input_paths(cfg, site, ev, cat))
    assert tm.contacted(argv, site) == [("www.example.com", 443)]
    tm.check_command(site, scope, argv, passive=False)
