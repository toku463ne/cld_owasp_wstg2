"""Raw request background runner and Tools tab (WSTG-INPV-16 step 2)."""
from __future__ import annotations

import json
import time
from datetime import date, timedelta

import pytest

from conftest import csrf_of
from wstg import evidence as evmod
from wstg import targets as tm
from wstg import rawreq_run as rawrun


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
    (d / "katana.txt").write_text("https://www.example.com/admin\nhttps://www.example.com/login\n")
    (tm.evidence_dir(cfg, t) / "katana-crawl" / "latest").symlink_to("v0001")


REAL = rawrun.command


@pytest.fixture
def sleeper(monkeypatch):
    seen = []

    def command(cfg, t, base_url, paths, requests, stop_file, *, oversized=False):
        seen.append(REAL(cfg, t, base_url, paths, requests, stop_file, oversized=oversized))
        return ["sleep", "30"]
    monkeypatch.setattr(rawrun, "command", command)
    return seen


def post(client, path, **data):
    data["csrf"] = csrf_of(client)
    return client.post(path, data=data)


def test_candidates_include_parser_battery(cfg, web_site):
    cands = rawrun.candidates(cfg, web_site, "https://www.example.com", [])
    assert any(c["kind"] == "parser" for c in cands)


def test_candidates_seed_paths_from_crawl(cfg, web_site):
    _put_katana(cfg, web_site)
    cands = rawrun.candidates(cfg, web_site, "https://www.example.com", [])
    norm = [c for c in cands if c["kind"] == "normalize"]
    assert any("/admin" in c["path"] for c in norm)


def test_command_builds(cfg, web_site):
    d = rawrun.folder(cfg, web_site)
    argv = rawrun.command(cfg, web_site, "https://www.example.com", ["/admin"], [], d / "stop")
    assert "--agree" in argv and "--all" in argv and "--path" in argv and "--agree-oversized" not in argv
    argv2 = rawrun.command(cfg, web_site, "https://www.example.com", [], [], d / "stop", oversized=True)
    assert "--agree-oversized" in argv2


def test_web_page_and_guards(admin_client, guest_client, cfg, web_site):
    assert "Raw request probe" in admin_client.get("/t/www.example.com/tools").get_data(as_text=True)
    page = admin_client.get("/t/www.example.com/tools/raw").get_data(as_text=True)
    assert "Blocked internal paths" in page and "destabilise the parser" in page
    assert "Probe (all candidates" not in guest_client.get("/t/www.example.com/tools/raw").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/tools/raw/start", agree="1").status_code == 403


def test_web_start_requires_agreement_then_runs(admin_client, cfg, web_site, sleeper):
    post(admin_client, "/t/www.example.com/tools/raw/start", paths="/admin")
    assert rawrun.status(cfg, web_site) is None and not sleeper
    r = post(admin_client, "/t/www.example.com/tools/raw/start", paths="/admin", agree="1", oversized="1")
    assert r.status_code == 302
    try:
        assert "--agree" in sleeper[0] and "--agree-oversized" in sleeper[0] and "--path" in sleeper[0]
        page = admin_client.get("/t/www.example.com/tools/raw").get_data(as_text=True)
        assert "running" in page and ">Stop</button>" in page
        post(admin_client, "/t/www.example.com/tools/raw/stop", how="stop")
        assert rawrun.status(cfg, web_site)["stop_request"]
    finally:
        rawrun.kill(cfg, web_site)


def test_add_finished_to_raw_request_tests(admin_client, cfg, db, web_site):
    d = rawrun.folder(cfg, web_site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "label": "all items",
                                              "started": "2026-01-01T00:00:00Z", "started_ts": time.time()}))
    (d / "raw.log").write_text("# started\n[1/1] #1 normalize /admin\n    => SUSPECTED-bypass: ...\n")
    st = rawrun.status(cfg, web_site)
    assert st["finished"] and not st["added"]
    r = post(admin_client, "/t/www.example.com/tools/raw/add", caption="raw 1")
    assert r.status_code == 302
    v = evmod.Store(cfg, db).load("www.example.com", "raw-request-tests")
    assert v and "raw/malformed request probe" in (v.path / v.items[0].file).read_text()
    assert rawrun.status(cfg, web_site)["added"]


def test_start_refuses_unsaved_result(cfg, web_site):
    d = rawrun.folder(cfg, web_site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "label": "1", "started_ts": time.time()}))
    (d / "raw.log").write_text("# started\n[1/1] #1 normalize /admin\n    => blocked\n")
    assert rawrun.status(cfg, web_site)["finished"]
    with pytest.raises(rawrun.RawRunError, match="not saved"):
        rawrun.start(cfg, web_site, base_url="https://www.example.com", paths=["/admin"], requests=[], actor="a")
    rawrun.start(cfg, web_site, base_url="https://www.example.com", paths=["/admin"], requests=[], actor="a",
                 discard=True)
    rawrun.kill(cfg, web_site)


def test_start_passes_proxy_env(cfg, web_site):
    import dataclasses
    paced = dataclasses.replace(cfg, http_proxy="http://127.0.0.1:3128")
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            seen["env"] = kw.get("env")
            self.pid = 424242
    rawrun.start(paced, web_site, base_url="https://www.example.com", paths=[], requests=[], actor="a",
                 popen=FakePopen)
    assert seen["env"]["http_proxy"] == "http://127.0.0.1:3128"


def test_evidence_links_to_the_raw_tool(admin_client, web_site):
    page = admin_client.get("/t/www.example.com/evidence/raw-request-tests").get_data(as_text=True)
    assert "/t/www.example.com/tools/raw" in page
