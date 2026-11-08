"""Browser HAR capture (src/wstg/capture.py), with a fake browser driver.

The driver is replaced so no real Chromium or Playwright is needed: tests cover
the scope checks, that the recorded HAR and storage state land as a new
har-browse version, and that out-of-scope hosts are reported.
"""
import json
from datetime import date, timedelta

import pytest

from wstg import capture as cap
from wstg import evidence as evmod
from wstg import targets as tm


@pytest.fixture
def store(cfg, db):
    return evmod.Store(cfg, db)


def _authorize(db, target):
    today = date.today()
    tm.update_scope(db, target, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="AUTH-1",
                    valid_from=str(today - timedelta(days=1)),
                    valid_until=str(today + timedelta(days=30)), actor="test")


@pytest.fixture
def site(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    t = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    _authorize(db, t)
    return tm.get(db, "www.example.com")


def _har(entries):
    return {"log": {"version": "1.2", "entries": entries}}


def fake_drive(contacts=("https://www.example.com/", "https://cdn.other.test/a.js")):
    """Build a drive() stand-in that writes a HAR + state and reports `contacts`."""
    def drive(url, har_path, state_path, *, headless, on_request):
        for c in contacts:
            on_request(c)
        har_path.write_text(json.dumps(_har([
            {"request": {"method": "GET", "url": url, "cookies": [], "headers": [], "postData": {}},
             "response": {"headers": [{"name": "Set-Cookie", "value": "SID=secret; Path=/"}]}},
        ])))
        state_path.write_text(json.dumps({"cookies": [{"name": "SID", "value": "secret"}], "origins": []}))
    return drive


def test_capture_stores_har_and_state_as_har_browse(cfg, db, store, site):
    res = cap.record_session(cfg, db, store, site, role="user", drive=fake_drive())
    ver = store.load("www.example.com", "har-browse")
    assert ver is not None
    files = [i.file for i in ver.items]
    assert any(f.endswith(".har") for f in files)
    assert any(f.endswith(".json") for f in files)     # storage state kept too
    assert res["state_file"] and res["state_file"].endswith(".json")
    # the .har is readable by the analyser and the glob used in the scenarios
    har = [i for i in ver.items if i.file.endswith(".har")][0]
    text = (ver.path / har.file).read_text()
    assert json.loads(text)["log"]["entries"]


def test_capture_flags_out_of_scope_hosts(cfg, db, store, site):
    res = cap.record_session(cfg, db, store, site, drive=fake_drive())
    assert "www.example.com" in res["in_scope_hosts"]
    assert res["out_of_scope_hosts"] == ["cdn.other.test"]


def test_capture_only_in_scope_when_no_third_party(cfg, db, store, site):
    res = cap.record_session(cfg, db, store, site,
                             drive=fake_drive(contacts=("https://www.example.com/x",)))
    assert res["out_of_scope_hosts"] == []


def test_capture_refuses_domain_target(cfg, db, store):
    tm.create(db, cfg, "example.com", "domain")
    dom = tm.get(db, "example.com")
    with pytest.raises(cap.CaptureError):
        cap.record_session(cfg, db, store, dom, drive=fake_drive())


def test_capture_refuses_unauthorized_scope(cfg, db, store):
    tm.create(db, cfg, "example.com", "domain")
    t = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    # default scope has no authorization reference / validity period
    with pytest.raises(tm.ScopeError):
        cap.record_session(cfg, db, store, tm.get(db, "www.example.com"), drive=fake_drive())


def test_capture_refuses_start_url_out_of_scope(cfg, db, store, site):
    with pytest.raises(tm.ScopeError):
        cap.record_session(cfg, db, store, site, start_url="https://evil.test/",
                           drive=fake_drive())


def test_capture_errors_when_no_har_recorded(cfg, db, store, site):
    def drive(url, har_path, state_path, *, headless, on_request):
        pass   # writes nothing
    with pytest.raises(cap.CaptureError):
        cap.record_session(cfg, db, store, site, drive=drive)
