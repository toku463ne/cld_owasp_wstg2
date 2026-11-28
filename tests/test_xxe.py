"""XML injection / XXE probe (WSTG-INPV-07 step 2) against loopback apps."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wstg import xxe


# ---- a HAR with one XML POST request -----------------------------------------------

def _har(tmp_path, base, path="/api", body='<?xml version="1.0"?>\n<order><item>book</item></order>',
         ctype="application/xml"):
    folder = tmp_path / "har"
    folder.mkdir(exist_ok=True)
    entry = {"request": {"method": "POST", "url": f"{base}{path}",
                         "headers": [{"name": "Content-Type", "value": ctype}],
                         "postData": {"mimeType": ctype, "text": body}}}
    (folder / "browse.har").write_text(json.dumps({"log": {"entries": [entry]}}))
    return str(folder)


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _XmlApp(BaseHTTPRequestHandler):
    """Base: subclasses set reply(body_text) -> response string."""
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        body = self.reply(raw).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def reply(self, raw):
        return "<p>ok</p>"


def _run(tmp_path, base, extra=None):
    har = _har(tmp_path, base) if extra is None else extra
    return xxe.main(["--base", base + "/", "--har", har, "--all", "--agree"])


# ---- unit tests for the body surgery -----------------------------------------------

def test_inject_text_into_text_node():
    out = xxe._inject_text("<a><b>hello</b></a>", "X-")
    assert "<b>X-hello</b>" in out


def test_root_name_and_doctype_prepend():
    xml = '<?xml version="1.0"?>\n<order><item>x</item></order>'
    body = xxe._xxe_body(xml, "deadbeef")
    assert body.startswith('<?xml version="1.0"?>')
    assert '<!DOCTYPE order [<!ENTITY wstgext SYSTEM "file:///nonexistent/wstg-deadbeef">]>' in body
    assert "&wstgext;" in body


# ---- end-to-end against loopback apps ----------------------------------------------

def test_structure_break_detected(tmp_path, capsys):
    class App(_XmlApp):
        def reply(self, raw):
            # A naive parser: a bare '&' or a mismatched tag is "not well-formed".
            if "&wstgx;" in raw or "</wstgx>" in raw:
                return "<p>org.xml.sax.SAXParseException: not well-formed (invalid token)</p>"
            return "<p>ok</p>"
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert _run(tmp_path, base) == 0
        assert "SUSPECTED-xml-struct" in capsys.readouterr().out
    finally:
        srv.shutdown()


def test_inband_xxe_detected(tmp_path, capsys):
    class App(_XmlApp):
        def reply(self, raw):
            # Vulnerable: resolves the external entity, fails to load the path, and leaks
            # the failed path in an error (in-band signal).
            import re
            m = re.search(r'SYSTEM "(file:///nonexistent/wstg-[0-9a-f]+)"', raw)
            if m:
                return f"<error>I/O warning : failed to load external entity \"{m.group(1)}\"</error>"
            return "<p>ok</p>"
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert _run(tmp_path, base) == 0
        out = capsys.readouterr().out
        assert "SUSPECTED-xxe-inband" in out
        assert "1 XML request(s) SUSPECTED" in out
    finally:
        srv.shutdown()


def test_body_echo_is_inconclusive_not_xxe(tmp_path, capsys):
    class App(_XmlApp):
        def reply(self, raw):
            return f"<echo>{raw}</echo>"            # echoes the whole body verbatim
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert _run(tmp_path, base) == 0
        out = capsys.readouterr().out
        assert "inconclusive-echo" in out
        assert "SUSPECTED-xxe-inband" not in out
    finally:
        srv.shutdown()


def test_safe_app_is_clean(tmp_path, capsys):
    class App(_XmlApp):
        def reply(self, raw):
            return "<result>accepted</result>"     # ignores entities, no error, no echo
    srv = _serve(App)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert _run(tmp_path, base) == 0
        out = capsys.readouterr().out
        assert "=> clean" in out
        assert "SUSPECTED" not in out.split("# verdict")[0]
    finally:
        srv.shutdown()


def test_list_sends_nothing(tmp_path, capsys):
    srv = _serve(_XmlApp)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        har = _har(tmp_path, base)
        assert xxe.main(["--base", base + "/", "--har", har, "--list"]) == 0
        out = capsys.readouterr().out
        assert "POST" in out and "/api" in out
    finally:
        srv.shutdown()


def test_agree_required(tmp_path, capsys):
    srv = _serve(_XmlApp)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        har = _har(tmp_path, base)
        assert xxe.main(["--base", base + "/", "--har", har, "--all"]) == 2
        assert "pass --agree" in capsys.readouterr().err
    finally:
        srv.shutdown()


def test_non_xml_request_ignored(tmp_path, capsys):
    srv = _serve(_XmlApp)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        har = _har(tmp_path, base, body="name=x&id=5", ctype="application/x-www-form-urlencoded")
        assert xxe.main(["--base", base + "/", "--har", har, "--list"]) == 0
        assert "no XML request found" in capsys.readouterr().out
    finally:
        srv.shutdown()
