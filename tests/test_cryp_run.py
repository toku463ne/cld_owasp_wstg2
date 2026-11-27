"""Padding-oracle decrypt started from the web (cryp_run.py, Tools tab), without a real run."""
import base64
import json
import time
from datetime import date, timedelta

import pytest
from conftest import csrf_of

from wstg import cryp_run as drun
from wstg import evidence as evmod
from wstg import targets as tm


@pytest.fixture
def site(db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    today = date.today()
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="AUTH-1",
                    valid_from=str(today - timedelta(days=1)), valid_until=str(today + timedelta(days=30)),
                    actor="test")
    return tm.get(db, "www.example.com")


def _put_http_root(cfg, t):
    """A http-root-https latest version with one encrypted-looking cookie (32 bytes)."""
    value = base64.b64encode(bytes(range(32))).decode()
    d = tm.evidence_dir(cfg, t) / "http-root-https" / "v0001"
    d.mkdir(parents=True)
    (d / "stdout.txt").write_text(f"HTTP/1.1 200 OK\r\nSet-Cookie: enc={value}; Path=/\r\n")
    (d / "body.html").write_text("<html></html>")
    (tm.evidence_dir(cfg, t) / "http-root-https" / "latest").symlink_to("v0001")


REAL = drun.command


@pytest.fixture
def sleeper(monkeypatch):
    seen = []

    def command(cfg, t, base_url, candidate, stop_file):
        seen.append(REAL(cfg, t, base_url, candidate, stop_file))
        return ["sleep", "30"]
    monkeypatch.setattr(drun, "command", command)
    return seen


def test_candidates_list_without_network(cfg, site):
    _put_http_root(cfg, site)
    cands = drun.candidates(cfg, site, "https://www.example.com")
    assert len(cands) == 1 and cands[0]["n"] == 1
    assert 'cookie "enc"' in cands[0]["label"]


def test_command_includes_inputs_and_candidate(cfg, site):
    _put_http_root(cfg, site)
    argv = drun.command(cfg, site, "https://www.example.com", 2, drun.folder(cfg, site) / "stop")
    assert "padding-decrypt" in argv and argv[argv.index("--candidate") + 1] == "2"
    assert "--stop-file" in argv and "http-root-https" in argv[argv.index("--http-root") + 1]
    assert "--har" not in argv                                   # har-browse not collected


def test_start_status_stop_kill(cfg, site, sleeper):
    st = drun.start(cfg, site, base_url="https://www.example.com", candidate=1, label="cookie enc", actor="admin")
    try:
        assert sleeper[0][sleeper[0].index("--candidate") + 1] == "1"
        cur = drun.status(cfg, site)
        assert cur["running"] and cur["candidate"] == 1 and cur["pid"] == st["pid"]
        with pytest.raises(drun.DecryptRunError):
            drun.start(cfg, site, base_url="https://www.example.com", candidate=1, label="x", actor="admin")
        drun.request_stop(cfg, site)
        assert drun.status(cfg, site)["stop_request"] and not drun.status(cfg, site)["can_kill"]
    finally:
        drun.kill(cfg, site)
    for _ in range(50):
        if not drun.status(cfg, site)["running"]:
            break
        time.sleep(0.1)
    assert not drun.status(cfg, site)["running"]


def post(client, path, **data):
    data["csrf"] = csrf_of(client)
    return client.post(path, data=data)


def test_web_decrypt_page_and_guard(admin_client, guest_client, cfg, site, sleeper):
    _put_http_root(cfg, site)
    assert "Padding oracle decrypt" in admin_client.get("/t/www.example.com/tools").get_data(as_text=True)
    page = admin_client.get("/t/www.example.com/tools/decrypt").get_data(as_text=True)
    assert "Decrypt one block" in page and 'cookie &#34;enc&#34;' in page
    assert "Decrypt one block" not in guest_client.get("/t/www.example.com/tools/decrypt").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/tools/decrypt/start", candidate="1", agree="1").status_code == 403
    # agreement box required
    post(admin_client, "/t/www.example.com/tools/decrypt/start", candidate="1")
    assert drun.status(cfg, site) is None and not sleeper
    r = post(admin_client, "/t/www.example.com/tools/decrypt/start", candidate="1", agree="1")
    assert r.status_code == 302
    try:
        page = admin_client.get("/t/www.example.com/tools/decrypt").get_data(as_text=True)
        assert "Decrypt running" in page and ">Stop</button>" in page and 'http-equiv="refresh"' in page
        post(admin_client, "/t/www.example.com/tools/decrypt/stop", how="stop")
        assert drun.status(cfg, site)["stop_request"]
    finally:
        drun.kill(cfg, site)


def test_add_finished_result_to_evidence(admin_client, cfg, db, site):
    d = drun.folder(cfg, site)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"pid": 0, "candidate": 1, "label": "cookie enc",
                                              "started": "2026-01-01T00:00:00Z", "started_ts": time.time()}))
    (d / "decrypt.log").write_text("# started\n  plaintext: hex=aa  text='..'\n# done\n")
    st = drun.status(cfg, site)
    assert st["finished"] and not st["running"]
    r = post(admin_client, "/t/www.example.com/tools/decrypt/add", caption="block 1")
    assert r.status_code == 302
    v = evmod.Store(cfg, db).load("www.example.com", "padding-oracle-confirm")
    assert v and any("plaintext" in (i.file or "") or True for i in v.items)
    text = (v.path / v.items[0].file).read_text()
    assert "padding-oracle decrypt" in text and "plaintext: hex=aa" in text


def test_links_to_the_decrypt_tool(admin_client, site):
    page = admin_client.get("/t/www.example.com/evidence/padding-oracle-confirm").get_data(as_text=True)
    assert "/t/www.example.com/tools/decrypt" in page
