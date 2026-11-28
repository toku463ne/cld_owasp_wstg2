"""XXE background runner and Tools tab (WSTG-INPV-07 step 2)."""
from __future__ import annotations

import json
import time
from datetime import date, timedelta

import pytest

from conftest import csrf_of
from wstg import evidence as evmod
from wstg import targets as tm
from wstg import xxe_run as xxerun


@pytest.fixture
def web_site(db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    today = date.today()
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="AUTH-1",
                    valid_from=str(today - timedelta(days=1)), valid_until=str(today + timedelta(days=30)),
                    actor="test")
    return tm.get(db, "www.example.com")


def _put_har(cfg, t):
    d = tm.evidence_dir(cfg, t) / "har-browse" / "v0001"
    d.mkdir(parents=True)
    entry = {"request": {"method": "POST", "url": "https://www.example.com/soap/order",
                         "headers": [{"name": "Content-Type", "value": "application/xml"}],
                         "postData": {"mimeType": "application/xml",
                                      "text": '<?xml version="1.0"?>\n<order><item>book</item></order>'}}}
    (d / "browse.har").write_text(json.dumps({"log": {"entries": [entry]}}))
    (tm.evidence_dir(cfg, t) / "har-browse" / "latest").symlink_to("v0001")


REAL = xxerun.command


@pytest.fixture
def sleeper(monkeypatch):
    seen = []

    def command(cfg, t, base_url, requests, stop_file):
        seen.append(REAL(cfg, t, base_url, requests, stop_file))
        return ["sleep", "30"]
    monkeypatch.setattr(xxerun, "command", command)
    return seen


def post(client, path, **data):
    data["csrf"] = csrf_of(client)
    return client.post(path, data=data)


def test_candidates_reads_har(cfg, web_site):
    _put_har(cfg, web_site)
    cands = xxerun.candidates(cfg, web_site, "https://www.example.com")
    assert len(cands) == 1
    assert cands[0]["method"] == "POST" and "/soap/order" in cands[0]["template"]
    assert cands[0]["kind"] == "body"


def _put_katana(cfg, t):
    d = tm.evidence_dir(cfg, t) / "katana-crawl" / "v0001"
    d.mkdir(parents=True)
    (d / "katana.txt").write_text(
        "https://www.example.com/web/Manager.aspx?xslFile=a.xsl&xmlPreview=languages.xml\n")
    (tm.evidence_dir(cfg, t) / "katana-crawl" / "latest").symlink_to("v0001")


def test_candidates_from_crawl_param_ref(cfg, web_site):
    _put_katana(cfg, web_site)
    cands = xxerun.candidates(cfg, web_site, "https://www.example.com")
    refs = [c for c in cands if c["kind"] == "param-ref"]
    assert any(c["name"] == "xmlPreview" for c in refs)


def test_command_builds(cfg, web_site):
    _put_har(cfg, web_site)
    d = xxerun.folder(cfg, web_site)
    argv = xxerun.command(cfg, web_site, "https://www.example.com", [1], d / "stop")
    assert "--agree" in argv and argv.count("--request") == 1 and "--all" not in argv
    assert "--har" in argv
    argv2 = xxerun.command(cfg, web_site, "https://www.example.com", [], d / "stop")
    assert "--all" in argv2


def test_web_page_and_guards(admin_client, guest_client, cfg, web_site):
    _put_har(cfg, web_site)
    assert "XML injection / XXE" in admin_client.get("/t/www.example.com/tools").get_data(as_text=True)
    page = admin_client.get("/t/www.example.com/tools/xxe").get_data(as_text=True)
    assert "/soap/order" in page and "Probe (all selected)" in page
    assert "Probe (all selected)" not in guest_client.get("/t/www.example.com/tools/xxe").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/tools/xxe/start", request="1", agree="1").status_code == 403


def test_web_without_sources(admin_client, cfg, web_site):
    page = admin_client.get("/t/www.example.com/tools/xxe").get_data(as_text=True)
    assert "No crawl or capture yet" in page


def test_web_start_requires_agreement_then_runs(admin_client, cfg, web_site, sleeper):
    _put_har(cfg, web_site)
    post(admin_client, "/t/www.example.com/tools/xxe/start", request="1")
    assert xxerun.status(cfg, web_site) is None and not sleeper
    r = post(admin_client, "/t/www.example.com/tools/xxe/start", request="1", agree="1")
    assert r.status_code == 302
    try:
        assert sleeper[0].count("--request") == 1 and "--agree" in sleeper[0]
        page = admin_client.get("/t/www.example.com/tools/xxe").get_data(as_text=True)
        assert "running" in page and ">Stop</button>" in page
        post(admin_client, "/t/www.example.com/tools/xxe/stop", how="stop")
        assert xxerun.status(cfg, web_site)["stop_request"]
    finally:
        xxerun.kill(cfg, web_site)


def test_add_finished_to_xml_injection_tests(admin_client, cfg, db, web_site):
    d = xxerun.folder(cfg, web_site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "label": "1 XML request(s)",
                                              "started": "2026-01-01T00:00:00Z", "started_ts": time.time()}))
    (d / "xxe.log").write_text("# started\n[1/1] #1 POST /soap/order\n    => SUSPECTED-xxe-inband: ...\n")
    st = xxerun.status(cfg, web_site)
    assert st["finished"] and not st["added"]
    r = post(admin_client, "/t/www.example.com/tools/xxe/add", caption="xxe 1")
    assert r.status_code == 302
    v = evmod.Store(cfg, db).load("www.example.com", "xml-injection-tests")
    assert v and "XXE probe" in (v.path / v.items[0].file).read_text()
    assert xxerun.status(cfg, web_site)["added"]


def test_start_refuses_unsaved_result(cfg, web_site):
    d = xxerun.folder(cfg, web_site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "label": "1", "started_ts": time.time()}))
    (d / "xxe.log").write_text("# started\n[1/1] #1 POST /soap/order\n    => clean\n")
    assert xxerun.status(cfg, web_site)["finished"]
    with pytest.raises(xxerun.XxeRunError, match="not saved"):
        xxerun.start(cfg, web_site, base_url="https://www.example.com", requests=[1], actor="a")
    xxerun.start(cfg, web_site, base_url="https://www.example.com", requests=[1], actor="a", discard=True)
    xxerun.kill(cfg, web_site)


def test_start_passes_proxy_env(cfg, web_site):
    import dataclasses
    paced = dataclasses.replace(cfg, http_proxy="http://127.0.0.1:3128")
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            seen["env"] = kw.get("env")
            self.pid = 424242
    xxerun.start(paced, web_site, base_url="https://www.example.com", requests=[1], actor="a", popen=FakePopen)
    assert seen["env"]["http_proxy"] == "http://127.0.0.1:3128"


def test_evidence_links_to_the_xxe_tool(admin_client, web_site):
    page = admin_client.get("/t/www.example.com/evidence/xml-injection-tests").get_data(as_text=True)
    assert "/t/www.example.com/tools/xxe" in page
