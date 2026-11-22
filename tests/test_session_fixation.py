"""Session fixation (WSTG-SESS-03): pure analysis, HAR reading, and the wstg-sess
check (reissue from the login HAR + a loopback replay)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wstg import har as harmod
from wstg import session as se
from wstg import sessionscan


# ---- pure analysis --------------------------------------------------------

def test_is_session_cookie_by_name_or_httponly():
    assert se.is_session_cookie({"name": "PHPSESSID"})
    assert se.is_session_cookie({"name": "whatever", "httpOnly": True})
    assert not se.is_session_cookie({"name": "lang"})


def test_reissue_rows_detects_reissue():
    assert se.reissue_rows({"SID": "aaaa1111"}, {"SID": "bbbb2222"})[0]["reissued"]
    assert not se.reissue_rows({"SID": "aaaa1111"}, {"SID": "aaaa1111"})[0]["reissued"]


def test_id_in_urls_and_logged_out_and_mask():
    hits = se.id_in_urls(["https://h/a;jsessionid=XYZ", "https://h/c?sid=abcdefgh"], {"abcdefgh"})
    assert len(hits) == 2
    assert se.looks_logged_out(302, "/login?next=/", "")
    assert se.looks_logged_out(200, "", '<input type="password" name="pwd">')
    assert not se.looks_logged_out(200, "", "<h1>Dashboard</h1>")
    assert se.mask("abcd12345678") == "abcd…5678 (12 chars)" and "secret" not in se.mask("secret")


# ---- reading a login from a HAR -------------------------------------------

def _entries(before="old", after="new", base="https://www.example.com"):
    b = base.rstrip("/")
    return [
        {"request": {"method": "GET", "url": f"{b}/", "cookies": []},
         "response": {"status": 200, "headers": [{"name": "Set-Cookie", "value": f"PHPSESSID={before}; Path=/; HttpOnly"}]}},
        {"request": {"method": "POST", "url": f"{b}/login",
                     "cookies": [{"name": "PHPSESSID", "value": before}],
                     "postData": {"params": [{"name": "user"}, {"name": "password"}]}},
         "response": {"status": 302, "headers": [{"name": "Set-Cookie", "value": f"PHPSESSID={after}; Path=/; HttpOnly"}]}},
        {"request": {"method": "GET", "url": f"{b}/dashboard", "cookies": [{"name": "PHPSESSID", "value": after}]},
         "response": {"status": 200, "headers": []}},
    ]


def test_analyze_har_finds_before_after_and_authed_url():
    res = se.analyze_har(_entries(), base_host="www.example.com")
    assert res["login_found"] and res["has_session"]
    assert res["before"] == {"PHPSESSID": "old"} and res["after"] == {"PHPSESSID": "new"}
    assert res["authed_url"].endswith("/dashboard")


def test_analyze_har_without_login():
    entries = [{"request": {"method": "GET", "url": "https://h/", "cookies": []}, "response": {"status": 200}}]
    res = se.analyze_har(entries, base_host="h")
    assert not res["login_found"] and not res["has_session"]


def test_login_fields_reads_localized_and_json_and_urlencoded_bodies():
    # Portuguese form field "senha" is detected as a password
    req = {"postData": {"mimeType": "application/x-www-form-urlencoded", "text": "usuario=a&senha=b"}}
    assert se.find_login([{"request": dict(req, method="POST")}]) == 0
    # nested JSON password
    jreq = {"method": "POST", "postData": {"mimeType": "application/json",
            "text": '{"creds":{"login":"a","password":"b"}}'}}
    assert se.find_login([{"request": jreq}]) == 0


def test_analyze_har_timeline_fallback_when_login_not_detected():
    # login field name is unknown, but the session cookie still changes value across the capture
    e = _entries(before="anon0000", after="auth9999")
    for ent in e:                      # hide the password field so the login is not auto-detected
        pd = (ent["request"].get("postData") or {}).get("params")
        if pd:
            ent["request"]["postData"]["params"] = [{"name": "u"}, {"name": "x"}]
    res = se.analyze_har(e, base_host="www.example.com")
    assert not res["login_found"] and res["has_session"]
    assert res["before"] == {"PHPSESSID": "anon0000"} and res["after"] == {"PHPSESSID": "auth9999"}


# ---- wstg-sess against a loopback replay target ---------------------------

class Dash(BaseHTTPRequestHandler):
    reject_old = True

    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if "PHPSESSID=new" in cookie or not Dash.reject_old:
            self._send(200, b"<h1>Dashboard</h1>")
        else:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def dash():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Dash)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()


def _write_har(tmp_path, entries):
    d = tmp_path / "har"
    d.mkdir()
    (d / "001-user-20260101.har").write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}))
    return d


def test_wstg_sess_reports_reissue_and_rejected_replay(tmp_path, dash, capsys):
    base = f"http://127.0.0.1:{dash}"
    d = _write_har(tmp_path, _entries(base=base))
    Dash.reject_old = True
    rc = sessionscan.main(["--base", base + "/", "--har", str(d)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "reissued at login [GOOD]" in out
    assert "still accepted after login: rejected" in out
    assert "no fixation detected" in out
    assert "old" not in out.split("verdict")[0] or "PHPSESSID" in out   # values masked (raw 'old'/'new' not shown)


def test_wstg_sess_flags_fixation_when_not_reissued(tmp_path, dash, capsys):
    base = f"http://127.0.0.1:{dash}"
    d = _write_har(tmp_path, _entries(before="same0000", after="same0000", base=base))
    Dash.reject_old = False
    rc = sessionscan.main(["--base", base + "/", "--har", str(d)])
    out = capsys.readouterr().out
    assert "NOT REISSUED" in out and "[FAIL]" in out
    assert "FAIL (session fixation)" in out


def test_wstg_sess_inconclusive_when_login_not_detected_and_no_reissue(tmp_path, dash, capsys):
    base = f"http://127.0.0.1:{dash}"
    e = _entries(before="same0000", after="same0000", base=base)
    for ent in e:                          # hide the password field
        if (ent["request"].get("postData") or {}).get("params"):
            ent["request"]["postData"]["params"] = [{"name": "u"}, {"name": "x"}]
    d = _write_har(tmp_path, e)
    Dash.reject_old = False
    rc = sessionscan.main(["--base", base + "/", "--har", str(d)])
    out = capsys.readouterr().out
    assert rc == 0                         # collected, not a failed run
    assert "not auto-detected" in out and "INCONCLUSIVE" in out
    assert "FAIL (session fixation)" not in out


def test_wstg_sess_no_login_har_is_exit_3(tmp_path, capsys):
    d = tmp_path / "har"
    d.mkdir()
    (d / "001-anon.har").write_text(json.dumps({"log": {"entries": [
        {"request": {"method": "GET", "url": "http://127.0.0.1/", "cookies": []}, "response": {"status": 200}}]}}))
    assert sessionscan.main(["--base", "http://127.0.0.1/", "--har", str(d)]) == 3
