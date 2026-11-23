import base64
import re
import http.server
import json
import threading
from datetime import date, timedelta

import pytest
from conftest import csrf_of

from wstg import replay as rp
from wstg import targets as tm

BURP = (b"POST /WEB/app/Manager.aspx HTTP/1.1\r\n"
        b"Host: www.example.com\r\n"
        b"Cookie: sid=abc; lang=en\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 501\r\n"
        b"Te: trailers\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
        b"spcNumber=test&x=1\n")


def test_parse_and_clean_a_burp_request():
    req = rp.apply(rp.parse_raw(BURP))
    assert req.url == "https://www.example.com/WEB/app/Manager.aspx"
    assert req.body == b"spcNumber=test&x=1"                      # pasted line break removed
    names = [k.lower() for k, _ in req.headers]
    assert "connection" not in names and "te" not in names and "content-length" not in names
    assert req.header("accept-encoding") == "gzip, deflate"        # br cannot be decoded here
    assert b"Content-Length: 18\r\n" in req.raw()
    assert not req.safe


def test_scheme_and_port():
    assert rp.parse_raw("GET / HTTP/1.1\nHost: www.example.com:80\n\n").url == "http://www.example.com/"
    assert rp.parse_raw("GET / HTTP/1.1\nHost: www.example.com:8443\n\n").url == "https://www.example.com:8443/"
    assert rp.parse_raw("GET / HTTP/1.1\nHost: www.example.com\n\n", "http").port == 80
    r = rp.parse_raw("GET http://www.example.com:8080/a?b=1 HTTP/1.1\n\n")
    assert (r.scheme, r.host, r.port, r.path) == ("http", "www.example.com", 8080, "/a?b=1")
    with pytest.raises(rp.ReplayError):
        rp.parse_raw("GET / HTTP/1.1\nAccept: */*\n\n")
    with pytest.raises(rp.ReplayError):
        rp.parse_raw("hello world\n")


def test_changes():
    req = rp.apply(rp.parse_raw(BURP), headers=["X-Test: 1", "Origin:"], cookies=["sid=new"],
                   params=["spcNumber=a b", "added=1"])
    assert req.header("x-test") == "1"
    assert req.header("cookie") == "lang=en; sid=new"
    assert req.body == b"spcNumber=a+b&x=1&added=1"
    g = rp.apply(rp.parse_raw("GET /s?q=1&p=2 HTTP/1.1\nHost: www.example.com\nCookie: a=1\n\n"),
                 params=["q=<x>", "new=y"], no_cookies=True)
    assert g.path == "/s?q=%3Cx%3E&p=2&new=y" and not g.header("cookie")
    j = rp.apply(rp.parse_raw('POST /api HTTP/1.1\nHost: www.example.com\nContent-Type: application/json\n\n'
                              '{"id": 5, "name": "a"}\n'), params=["id=7", "name=b"])
    assert json.loads(j.body) == {"id": 7, "name": "b"}
    m = rp.apply(rp.parse_raw(BURP), method="get", path="/other?z=1", body=b"")
    assert (m.method, m.path, m.body) == ("GET", "/other?z=1", b"")
    with pytest.raises(rp.ReplayError):
        rp.apply(rp.parse_raw(BURP), headers=["Bad Name: x"])


def test_burp_xml_export():
    raw = base64.b64encode(b"GET /x HTTP/1.1\r\nHost: www.example.com\r\n\r\n").decode()
    xml = (f'<?xml version="1.0"?><items burpVersion="2024"><item><url><![CDATA[http://www.example.com:8080/x]]></url>'
           f'<host ip="192.0.2.1">www.example.com</host><port>8080</port><protocol>http</protocol>'
           f'<request base64="true"><![CDATA[{raw}]]></request></item></items>').encode()
    req = rp.load(xml)
    assert req.url == "http://www.example.com:8080/x"
    with pytest.raises(rp.ReplayError):
        rp.load(xml, item=2)


def test_curl_and_python_output():
    req = rp.apply(rp.parse_raw(BURP))
    curl = rp.to_curl(req)
    assert curl.startswith("curl -sk -i --http1.1 --path-as-is")
    assert "-H 'Cookie: sid=abc; lang=en'" in curl and "--data-binary spcNumber=test&x=1" not in curl
    assert "--data-binary 'spcNumber=test&x=1'" in curl and curl.endswith("https://www.example.com/WEB/app/Manager.aspx")
    script = rp.to_python(req)
    compile(script, "replay.py", "exec")
    assert "BODY = b'spcNumber=test&x=1'" in script


class _Handler(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Handler.seen.append((self.path, dict(self.headers), body))
        out = b"<html><title>Done</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    s = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    _Handler.seen.clear()
    yield s.server_address[1]
    s.shutdown()


def test_cli_sends_to_loopback(server, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    f = tmp_path / "req.txt"
    f.write_bytes(BURP.replace(b"www.example.com", f"127.0.0.1:{server}".encode()))
    rc = rp.main([str(f), "--scheme", "http", "-p", "x=2", "--repeat", "2", "--pause", "0", "--out", str(tmp_path / "o")])
    out = capsys.readouterr().out
    assert rc == 0 and "200 OK" in out and "title: Done" in out
    assert len(_Handler.seen) == 2 and _Handler.seen[0][2] == b"spcNumber=test&x=2"
    assert "Connection" not in _Handler.seen[0][1] or _Handler.seen[0][1]["Connection"] != "keep-alive"
    assert (tmp_path / "o" / "response-2.txt").read_bytes().startswith(b"HTTP/1.1 200 OK")
    assert rp.main([str(tmp_path / "missing.txt")]) == 2


# ---- web Tools tab


def post(client, url, **data):
    data["csrf"] = csrf_of(client)
    return client.post(url, data=data)


def _target(db, cfg, authorize=True):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    if authorize:
        today = date.today()
        tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443",
                        base_url="https://www.example.com", authorization_ref="AUTH-1",
                        valid_from=str(today - timedelta(days=1)), valid_until=str(today + timedelta(days=30)),
                        actor="test")
    return t


def test_tools_tab_and_convert(guest_client, db, cfg):
    _target(db, cfg)
    page = guest_client.get("/t/www.example.com/tools").get_data(as_text=True)
    assert "Request replay" in page and ">Tools</a>" in page
    r = post(guest_client, "/t/www.example.com/tools/replay", raw=BURP.decode(), action="convert",
             params="spcNumber=zz")
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and "curl -sk" in page and "spcNumber=zz" in page
    assert "wstg-replay request.txt -p spcNumber=zz" in page
    assert "Send once" not in page                                  # guest is read-only
    assert post(guest_client, "/t/www.example.com/tools/replay", raw=BURP.decode(), action="send").status_code == 403
    r = post(guest_client, "/t/www.example.com/tools/replay", raw="nonsense", action="convert")
    assert r.status_code == 400 and "not a request line" in r.get_data(as_text=True)


def test_send_is_scope_checked_and_needs_agreement(admin_client, db, cfg, monkeypatch):
    _target(db, cfg)
    sent = []

    def fake_send(req, proxy=""):
        sent.append(req)
        return rp.Response(200, "OK", [("Content-Type", "text/html")], b"<title>Hi</title>", 0.1, 17)
    monkeypatch.setattr(rp, "send", fake_send)
    other = BURP.decode().replace("www.example.com", "evil.example.net")
    r = post(admin_client, "/t/www.example.com/tools/replay", raw=other, action="send", agree="1")
    assert r.status_code == 403 and "not in the scope" in r.get_data(as_text=True) and not sent
    r = post(admin_client, "/t/www.example.com/tools/replay", raw=BURP.decode(), action="send")
    assert r.status_code == 400 and "may change the target" in r.get_data(as_text=True) and not sent
    r = post(admin_client, "/t/www.example.com/tools/replay", raw=BURP.decode(), action="send", agree="1")
    assert r.status_code == 200 and "200 OK" in r.get_data(as_text=True) and len(sent) == 1
    get = "GET / HTTP/1.1\nHost: www.example.com\n\n"
    assert post(admin_client, "/t/www.example.com/tools/replay", raw=get, action="send").status_code == 200
    log = db.query("SELECT detail FROM audit_log WHERE action = 'tool.replay'")
    assert len(log) == 2 and "Cookie" not in log[0]["detail"]


def test_send_from_an_evidence_page_adds_request_and_response(admin_client, db, cfg, monkeypatch, app):
    t = _target(db, cfg)
    monkeypatch.setattr(rp, "send", lambda req, proxy="": rp.Response(
        302, "Found", [("Location", "/login")], b"moved", 0.1, 5))
    page = admin_client.get("/t/www.example.com/evidence/hijacking-tests").get_data(as_text=True)
    assert "/t/www.example.com/tools/replay?ev=hijacking-tests" in page
    page = admin_client.get("/t/www.example.com/tools/replay?ev=hijacking-tests").get_data(as_text=True)
    assert 'name="ev" value="hijacking-tests"' in page and ">Add to hijacking-tests</button>" not in page
    store = app.extensions["wstg.store"]
    raw = "GET /me HTTP/1.1\nHost: www.example.com\nCookie: sid=s1\n\n"
    r = post(admin_client, "/t/www.example.com/tools/replay", raw=raw, action="send", ev="hijacking-tests")
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and ">Add to hijacking-tests</button>" in page and "302 Found" in page
    assert store.load(t.name, "hijacking-tests") is None                 # nothing added by sending
    token = re.search(r'name="pending" value="([0-9a-f]{32})"', page).group(1)
    pending = cfg.evidence_root / "www.example.com" / "_replay" / f"{token}.json"
    assert pending.exists() and oct(pending.stat().st_mode & 0o777) == "0o600"
    # adding does not send again
    monkeypatch.setattr(rp, "send", lambda *a, **k: pytest.fail("sent again"))
    r = post(admin_client, "/t/www.example.com/tools/replay", raw=raw, action="save", ev="hijacking-tests",
             pending=token, caption="token in a second browser")
    assert r.status_code == 200 and "Added to" in r.get_data(as_text=True) and not pending.exists()
    v = store.load(t.name, "hijacking-tests")
    assert v.items[-1].caption == "token in a second browser"
    text = store.file_path(v, v.items[-1].file).read_text()
    assert "GET /me HTTP/1.1" in text and "Cookie: sid=s1" in text and "HTTP/1.1 302 Found" in text and "moved" in text
    # the same result cannot be added twice; a bad token or another evidence is refused
    r = post(admin_client, "/t/www.example.com/tools/replay", raw=raw, action="save", ev="hijacking-tests", pending=token)
    assert r.status_code == 400 and "is gone" in r.get_data(as_text=True)
    assert post(admin_client, "/t/www.example.com/tools/replay", raw=raw, action="save", ev="hijacking-tests",
                pending="../x").status_code == 400
    assert store.load(t.name, "hijacking-tests").version == v.version
    # auto evidence or unknown ID is refused
    assert admin_client.get("/t/www.example.com/tools/replay?ev=http-root-https").status_code == 404
    assert admin_client.get("/t/www.example.com/tools/replay?ev=nope").status_code == 404


def test_evidence_text_is_cut_to_the_text_limit():
    from wstg import evidence as evmod
    from wstg.web_tools import evidence_text
    req = rp.parse_raw("GET / HTTP/1.1\nHost: www.example.com\n\n")
    big = rp.Response(200, "OK", [], b"x" * (2 * evmod.MAX_TEXT_BYTES), 0.1, 0)
    text = evidence_text(req, big, "", "admin", "")
    assert len(text.encode()) <= evmod.MAX_TEXT_BYTES and "more bytes not kept" in text
    assert "no answer: timeout" in evidence_text(req, None, "no answer: timeout", "admin", "")
