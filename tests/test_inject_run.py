"""Injection probe background runner and Tools tab (WSTG-INPV active-probe steps)."""
from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

from conftest import csrf_of
from wstg import inject_run as irun
from wstg import targets as tm


@pytest.fixture
def web_site(db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    today = date.today()
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="AUTH-1",
                    valid_from=str(today - timedelta(days=1)), valid_until=str(today + timedelta(days=30)),
                    actor="test")
    return tm.get(db, "www.example.com")


def _put_katana(cfg, t):
    d = tm.evidence_dir(cfg, t) / "katana-crawl" / "v0001"
    d.mkdir(parents=True)
    (d / "katana.txt").write_text(
        "https://www.example.com/items?id=5\nhttps://www.example.com/search?q=a&page=2\n")
    (tm.evidence_dir(cfg, t) / "katana-crawl" / "latest").symlink_to("v0001")


REAL = irun.command


@pytest.fixture
def sleeper(monkeypatch):
    seen = []

    def command(cfg, t, base_url, pack, requests, stop_file):
        seen.append(REAL(cfg, t, base_url, pack, requests, stop_file))
        return ["sleep", "30"]
    monkeypatch.setattr(irun, "command", command)
    return seen


def post(client, path, **data):
    data["csrf"] = csrf_of(client)
    return client.post(path, data=data)


def test_candidates_reads_crawl(cfg, web_site):
    _put_katana(cfg, web_site)
    cands = irun.candidates(cfg, web_site, "https://www.example.com", "sqli")
    names = sorted(c["param"] for c in cands)
    assert "id" in names and "q" in names and "page" in names


def test_command_builds(cfg, web_site):
    _put_katana(cfg, web_site)
    d = irun.folder(cfg, web_site, "sqli")
    argv = irun.command(cfg, web_site, "https://www.example.com", "sqli", [1, 2], d / "stop")
    assert "--pack" in argv and argv[argv.index("--pack") + 1] == "sqli"
    assert "--agree" in argv and argv.count("--request") == 2 and "--all" not in argv
    argv2 = irun.command(cfg, web_site, "https://www.example.com", "sqli", [], d / "stop")
    assert "--all" in argv2


def test_web_page_lists_switch_and_guards(admin_client, guest_client, cfg, web_site):
    _put_katana(cfg, web_site)
    assert "Injection probe" in admin_client.get("/t/www.example.com/tools").get_data(as_text=True)
    page = admin_client.get("/t/www.example.com/tools/inject?pack=sqli").get_data(as_text=True)
    assert "/items" in page and "Probe (all selected)" in page and "SQL injection probe" in page
    ssti = admin_client.get("/t/www.example.com/tools/inject?pack=ssti").get_data(as_text=True)
    assert "Server-side template injection" in ssti
    assert "Probe (all selected)" not in guest_client.get("/t/www.example.com/tools/inject").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/tools/inject/start", pack="sqli", request="1",
                agree="1").status_code == 403


def test_web_without_sources(admin_client, cfg, web_site):
    page = admin_client.get("/t/www.example.com/tools/inject").get_data(as_text=True)
    assert "No crawl or capture yet" in page


def test_web_start_requires_agreement_then_runs(admin_client, cfg, web_site, sleeper):
    _put_katana(cfg, web_site)
    post(admin_client, "/t/www.example.com/tools/inject/start", pack="sqli", request="1")
    assert irun.status(cfg, web_site, "sqli") is None and not sleeper
    r = post(admin_client, "/t/www.example.com/tools/inject/start", pack="sqli", request=["1", "2"], agree="1")
    assert r.status_code == 302
    try:
        assert sleeper[0].count("--request") == 2 and "--pack" in sleeper[0]
        page = admin_client.get("/t/www.example.com/tools/inject?pack=sqli").get_data(as_text=True)
        assert "running" in page and ">Stop</button>" in page
        post(admin_client, "/t/www.example.com/tools/inject/stop", pack="sqli", how="stop")
        assert irun.status(cfg, web_site, "sqli")["stop_request"]
    finally:
        irun.kill(cfg, web_site, "sqli")


def test_packs_do_not_collide(cfg, web_site, sleeper):
    _put_katana(cfg, web_site)
    irun.start(cfg, web_site, base_url="https://www.example.com", pack="sqli", requests=[1], actor="a")
    irun.start(cfg, web_site, base_url="https://www.example.com", pack="ssti", requests=[1], actor="a")
    try:
        assert irun.status(cfg, web_site, "sqli")["running"]
        assert irun.status(cfg, web_site, "ssti")["running"]
        assert irun.folder(cfg, web_site, "sqli") != irun.folder(cfg, web_site, "ssti")
    finally:
        irun.kill(cfg, web_site, "sqli")
        irun.kill(cfg, web_site, "ssti")


def test_add_finished_to_sqli_tests(admin_client, cfg, db, web_site):
    import time as _t
    d = irun.folder(cfg, web_site, "sqli")
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "pack": "sqli", "label": "2 parameter(s)",
                                              "started": "2026-01-01T00:00:00Z", "started_ts": _t.time()}))
    (d / "inject.log").write_text("# started\n[1/2] #1 GET /items ?id\n    => SUSPECTED-error: '\\'' -> engine error\n")
    st = irun.status(cfg, web_site, "sqli")
    assert st["finished"] and not st["added"]
    r = post(admin_client, "/t/www.example.com/tools/inject/add", pack="sqli", caption="sqli 1")
    assert r.status_code == 302
    from wstg import evidence as evmod
    v = evmod.Store(cfg, db).load("www.example.com", "sqli-tests")
    assert v and "injection probe" in (v.path / v.items[0].file).read_text()
    assert irun.status(cfg, web_site, "sqli")["added"]


def test_start_refuses_unsaved_result(cfg, web_site, sleeper):
    import time as _t
    _put_katana(cfg, web_site)
    d = irun.folder(cfg, web_site, "sqli")
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "pack": "sqli", "label": "1", "started_ts": _t.time()}))
    (d / "inject.log").write_text("# started\n[1/1] #1 GET /items ?id\n    => clean\n")
    assert irun.status(cfg, web_site, "sqli")["finished"]
    with pytest.raises(irun.InjectRunError, match="not saved"):
        irun.start(cfg, web_site, base_url="https://www.example.com", pack="sqli", requests=[1], actor="a")
    irun.start(cfg, web_site, base_url="https://www.example.com", pack="sqli", requests=[1], actor="a", discard=True)
    irun.kill(cfg, web_site, "sqli")


def test_start_passes_proxy_env(cfg, web_site):
    import dataclasses
    _put_katana(cfg, web_site)
    paced = dataclasses.replace(cfg, http_proxy="http://127.0.0.1:3128")
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            seen["env"] = kw.get("env")
            self.pid = 424242
    irun.start(paced, web_site, base_url="https://www.example.com", pack="sqli", requests=[1],
               actor="a", popen=FakePopen)
    assert seen["env"]["http_proxy"] == "http://127.0.0.1:3128"


def test_links_to_the_inject_tool(admin_client, web_site):
    page = admin_client.get("/t/www.example.com/evidence/sqli-tests").get_data(as_text=True)
    assert "/t/www.example.com/tools/inject" in page and "pack=sqli" in page


@pytest.mark.parametrize("eid,pack", [
    ("ssti-tests", "ssti"), ("code-injection-tests", "code"),
    ("xpath-injection-tests", "xpath"), ("ldap-injection-tests", "ldap"),
    ("command-injection-tests", "cmd"), ("ssi-injection-tests", "ssi"),
    ("http-smuggling-tests", "crlf")])
def test_new_pack_evidence_links_to_tool(admin_client, web_site, eid, pack):
    page = admin_client.get(f"/t/www.example.com/evidence/{eid}").get_data(as_text=True)
    assert f"/t/www.example.com/tools/inject" in page and f"pack={pack}" in page


def test_pack_selector_lists_all(admin_client, cfg, web_site):
    _put_katana(cfg, web_site)
    page = admin_client.get("/t/www.example.com/tools/inject").get_data(as_text=True)
    for wstg in ("INPV-05", "INPV-18", "INPV-09", "INPV-06", "INPV-12", "INPV-08", "INPV-15"):
        assert wstg in page
