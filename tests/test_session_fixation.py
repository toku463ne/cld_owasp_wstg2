"""Session fixation (WSTG-SESS-03): pure analysis, and record_fixation with a fake
browser driver plus a loopback replay target."""

import threading
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wstg import capture as cap
from wstg import evidence as evmod
from wstg import session as se
from wstg import targets as tm


# ---- pure analysis --------------------------------------------------------

def test_is_session_cookie_by_name_or_httponly():
    assert se.is_session_cookie({"name": "PHPSESSID"})
    assert se.is_session_cookie({"name": "whatever", "httpOnly": True})
    assert not se.is_session_cookie({"name": "lang"})


def test_reissue_rows_detects_reissue_and_survival():
    before = {"SID": "aaaa1111"}
    rows = se.reissue_rows(before, {"SID": "bbbb2222"})
    assert rows[0]["reissued"] and "reissued at login" in rows[0]["state"]
    rows = se.reissue_rows(before, {"SID": "aaaa1111"})
    assert not rows[0]["reissued"] and "NOT REISSUED" in rows[0]["state"]
    rows = se.reissue_rows(before, {"SID": "chosen"}, injected={"SID": "chosen"})
    assert rows[0]["injected_survived"]


def test_id_in_urls_and_logged_out():
    urls = ["https://h/a;jsessionid=XYZ", "https://h/b?x=1", "https://h/c?sid=abcdefgh"]
    hits = se.id_in_urls(urls, {"abcdefgh"})
    assert any("jsessionid" in u for u in hits) and any("sid=" in u for u in hits)
    assert se.looks_logged_out(302, "/login?next=/", "")
    assert se.looks_logged_out(200, "", '<input type="password" name="pwd">')
    assert not se.looks_logged_out(200, "", "<h1>Dashboard</h1>")


def test_mask_hides_the_value():
    assert se.mask("abcd12345678") == "abcd…5678 (12 chars)"
    assert "secret" not in se.mask("secret")


# ---- record_fixation with a fake driver -----------------------------------

@pytest.fixture
def store(cfg, db):
    return evmod.Store(cfg, db)


@pytest.fixture
def site(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    t = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    today = date.today()
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="A-1",
                    valid_from=str(today - timedelta(days=1)), valid_until=str(today + timedelta(days=30)),
                    actor="test")
    return tm.get(db, "www.example.com")


def fake_drive(before, after, *, injected=None, final_url="", urls=()):
    def drive(url, marker, *, headless, on_request):
        for u in urls:
            on_request(u)
        return {"before": before, "after": after, "final_url": final_url, "injected": injected or {}}
    return drive


def test_reissued_at_login_is_not_a_fail(cfg, db, store, site):
    drive = fake_drive([{"name": "PHPSESSID", "value": "aaaa1111", "httpOnly": True}],
                       [{"name": "PHPSESSID", "value": "bbbb2222", "httpOnly": True}])
    res = cap.record_fixation(cfg, db, store, site, drive=drive)
    assert not res["fail"] and not res["not_reissued"]
    text = (store.load("www.example.com", "session-reissue-tests").path /
            store.load("www.example.com", "session-reissue-tests").items[0].file).read_text()
    assert "reissued at login [GOOD]" in text and "aaaa1111" not in text    # value masked


def test_not_reissued_and_url_id_are_fails(cfg, db, store, site):
    drive = fake_drive([{"name": "PHPSESSID", "value": "same0000", "httpOnly": True}],
                       [{"name": "PHPSESSID", "value": "same0000", "httpOnly": True}],
                       urls=["https://www.example.com/app;jsessionid=same0000"])
    res = cap.record_fixation(cfg, db, store, site, drive=drive)
    assert res["fail"] and res["not_reissued"] == ["PHPSESSID"] and res["url_hits"]


def test_injected_identifier_that_survives_is_a_fail(cfg, db, store, site):
    drive = fake_drive([{"name": "PHPSESSID", "value": "anon1234", "httpOnly": True}],
                       [{"name": "PHPSESSID", "value": "chosen99", "httpOnly": True}],
                       injected={"PHPSESSID": "chosen99"})
    res = cap.record_fixation(cfg, db, store, site, drive=drive)
    assert res["injected_survived"] == ["PHPSESSID"] and res["fail"]


# ---- the active replay against a loopback target --------------------------

class Replay(BaseHTTPRequestHandler):
    reject_old = True

    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if "SID=new" in cookie or (not Replay.reject_old):
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
def replay_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Replay)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()


def _scope(port):
    return tm.Scope(allowed_hosts=("127.0.0.1",), allowed_ports=(port,),
                    base_url=f"http://127.0.0.1:{port}", authorization_ref="A", valid_from=None,
                    valid_until=None, updated_at="", updated_by="")


def test_replay_old_id_rejected(replay_server):
    Replay.reject_old = True
    snap = {"before": [{"name": "SID", "value": "old"}], "after": [{"name": "SID", "value": "new"}],
            "final_url": f"http://127.0.0.1:{replay_server}/app"}
    assert cap._replay_old_id(snap, _scope(replay_server))["verdict"] == "rejected"


def test_replay_old_id_still_accepted(replay_server):
    Replay.reject_old = False
    snap = {"before": [{"name": "SID", "value": "old"}], "after": [{"name": "SID", "value": "new"}],
            "final_url": f"http://127.0.0.1:{replay_server}/app"}
    assert cap._replay_old_id(snap, _scope(replay_server))["verdict"] == "still accepted"


def test_replay_skipped_when_out_of_scope(replay_server):
    snap = {"before": [{"name": "SID", "value": "old"}], "after": [{"name": "SID", "value": "new"}],
            "final_url": "http://192.0.2.9/app"}
    assert cap._replay_old_id(snap, _scope(replay_server))["verdict"] == "not tested"
