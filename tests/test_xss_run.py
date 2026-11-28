"""Reflected XSS confirm background runner and Tools tab (WSTG-INPV-01 step 4)."""
from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

from conftest import csrf_of
from wstg import targets as tm
from wstg import xss_run as xrun


@pytest.fixture
def web_site(db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    today = date.today()
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="AUTH-1",
                    valid_from=str(today - timedelta(days=1)), valid_until=str(today + timedelta(days=30)),
                    actor="test")
    return tm.get(db, "www.example.com")


def _put_reflect(cfg, t):
    d = tm.evidence_dir(cfg, t) / "reflection-check" / "v0001"
    d.mkdir(parents=True)
    (d / "stdout.txt").write_text(
        '- /search ?q: REFLECTED-UNENCODED (HTTP 200 text/html; html: raw <)\n'
        '    url: https://www.example.com/search?q=wstgdeadbeef<"\'>\n'
        '- /profile ?name: REFLECTED-UNENCODED (HTTP 200 text/html; attribute ("-quoted): raw ")\n'
        '    url: https://www.example.com/profile?name=wstgdeadbeef<"\'>&id=5\n')
    (tm.evidence_dir(cfg, t) / "reflection-check" / "latest").symlink_to("v0001")


REAL = xrun.command


@pytest.fixture
def sleeper(monkeypatch):
    seen = []

    def command(cfg, t, base_url, candidates, stop_file, out):
        seen.append(REAL(cfg, t, base_url, candidates, stop_file, out))
        return ["sleep", "30"]
    monkeypatch.setattr(xrun, "command", command)
    return seen


def post(client, path, **data):
    data["csrf"] = csrf_of(client)
    return client.post(path, data=data)


def test_candidates_reads_reflection_check(cfg, web_site):
    _put_reflect(cfg, web_site)
    cands = xrun.candidates(cfg, web_site, "https://www.example.com")
    assert [c["param"] for c in cands] == ["q", "name"]
    assert cands[1]["where"] == 'attribute ("-quoted)'
    assert cands[0]["url"].startswith("https://www.example.com/search?q=")


def test_command_builds_candidates_and_all(cfg, web_site):
    _put_reflect(cfg, web_site)
    d = xrun.folder(cfg, web_site)
    argv = xrun.command(cfg, web_site, "https://www.example.com", [1], d / "stop", d)
    assert "--agree" in argv and "--stop-file" in argv and "--out" in argv
    assert argv.count("--candidate") == 1 and "--all" not in argv
    assert "--reflect" in argv
    argv2 = xrun.command(cfg, web_site, "https://www.example.com", [], d / "stop", d)
    assert "--all" in argv2 and "--candidate" not in argv2


def test_web_page_lists_and_guards(admin_client, guest_client, cfg, web_site):
    _put_reflect(cfg, web_site)
    assert "Reflected XSS confirm" in admin_client.get("/t/www.example.com/tools").get_data(as_text=True)
    page = admin_client.get("/t/www.example.com/tools/xss").get_data(as_text=True)
    assert "/search" in page and "/profile" in page and "Confirm in the browser" in page
    assert "Confirm in the browser" not in guest_client.get("/t/www.example.com/tools/xss").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/tools/xss/start", candidate="1", agree="1").status_code == 403


def test_web_without_reflection_check(admin_client, cfg, web_site):
    page = admin_client.get("/t/www.example.com/tools/xss").get_data(as_text=True)
    assert "No reflection-check yet" in page


def test_web_start_requires_agreement_then_runs(admin_client, cfg, web_site, sleeper):
    _put_reflect(cfg, web_site)
    post(admin_client, "/t/www.example.com/tools/xss/start", candidate="1")
    assert xrun.status(cfg, web_site) is None and not sleeper
    r = post(admin_client, "/t/www.example.com/tools/xss/start", candidate=["1", "2"], agree="1")
    assert r.status_code == 302
    try:
        assert sleeper[0].count("--candidate") == 2
        page = admin_client.get("/t/www.example.com/tools/xss").get_data(as_text=True)
        assert "XSS confirm running" in page and ">Stop</button>" in page and 'http-equiv="refresh"' in page
        post(admin_client, "/t/www.example.com/tools/xss/stop", how="stop")
        assert xrun.status(cfg, web_site)["stop_request"]
    finally:
        xrun.kill(cfg, web_site)


def test_web_all_when_none_selected(admin_client, cfg, web_site, sleeper):
    _put_reflect(cfg, web_site)
    r = post(admin_client, "/t/www.example.com/tools/xss/start", agree="1")
    assert r.status_code == 302
    try:
        assert "--all" in sleeper[0]
    finally:
        xrun.kill(cfg, web_site)


def test_add_finished_adds_text_and_screenshots(admin_client, cfg, db, web_site):
    import time as _t
    d = xrun.folder(cfg, web_site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "label": "2 parameter(s)",
                                              "started": "2026-01-01T00:00:00Z", "started_ts": _t.time()}))
    (d / "xss.log").write_text("# started\n[1/2] #1 q (html)\n    => CONFIRMED-EXECUTED (HTTP 200)\n")
    # a minimal valid PNG
    png = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
           b"\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00"
           b"\x00\x00IEND\xaeB`\x82")
    (d / "xss-q-1.png").write_bytes(png)
    st = xrun.status(cfg, web_site)
    assert st["finished"] and st["shots"] == ["xss-q-1.png"]
    r = post(admin_client, "/t/www.example.com/tools/xss/add", caption="confirm 1")
    assert r.status_code == 302
    from wstg import evidence as evmod
    v = evmod.Store(cfg, db).load("www.example.com", "xss-reflected-tests")
    kinds = sorted(it.type for it in v.items)
    assert "image" in kinds and "text" in kinds
    assert xrun.status(cfg, web_site)["added"]


def test_start_refuses_unsaved_previous_result(cfg, web_site, sleeper):
    import time as _t
    _put_reflect(cfg, web_site)
    d = xrun.folder(cfg, web_site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "label": "1 parameter(s)", "started_ts": _t.time()}))
    (d / "xss.log").write_text("# started\n[1/1] #1 q (html)\n    => CONFIRMED-EXECUTED\n")
    assert xrun.status(cfg, web_site)["finished"] and not xrun.status(cfg, web_site)["added"]
    with pytest.raises(xrun.XssRunError, match="not saved"):
        xrun.start(cfg, web_site, base_url="https://www.example.com", candidates=[2], actor="a")
    xrun.start(cfg, web_site, base_url="https://www.example.com", candidates=[2], actor="a", discard=True)
    try:
        assert not xrun.status(cfg, web_site)["added"]
    finally:
        xrun.kill(cfg, web_site)


def test_mark_added_lets_next_start(cfg, web_site, sleeper):
    import time as _t
    _put_reflect(cfg, web_site)
    d = xrun.folder(cfg, web_site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "label": "x", "started_ts": _t.time()}))
    (d / "xss.log").write_text("# done\n")
    xrun.mark_added(cfg, web_site)
    assert xrun.status(cfg, web_site)["added"]
    xrun.start(cfg, web_site, base_url="https://www.example.com", candidates=[1], actor="a")
    xrun.kill(cfg, web_site)


def test_start_passes_proxy_env(cfg, web_site):
    import dataclasses
    _put_reflect(cfg, web_site)
    paced = dataclasses.replace(cfg, http_proxy="http://127.0.0.1:3128")
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            seen["env"] = kw.get("env")
            self.pid = 424242
    xrun.start(paced, web_site, base_url="https://www.example.com", candidates=[1], actor="a", popen=FakePopen)
    assert seen["env"]["http_proxy"] == "http://127.0.0.1:3128"


def test_links_to_the_xss_tool(admin_client, web_site):
    page = admin_client.get("/t/www.example.com/evidence/xss-reflected-tests").get_data(as_text=True)
    assert "/t/www.example.com/tools/xss" in page
