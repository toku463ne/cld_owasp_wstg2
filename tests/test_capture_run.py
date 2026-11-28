"""Browser capture started from the web (capture_run.py, Tools tab), without a real browser."""
import json
import threading
import time
from datetime import date, timedelta

import pytest
from conftest import csrf_of

from wstg import capture as cap
from wstg import capture_run as crun
from wstg import cli
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


REAL_COMMAND = crun.command


@pytest.fixture
def sleeper(monkeypatch):
    """crun.start runs `sleep` instead of wstg capture; records the real command."""
    seen = []

    def command(t, role, url, stop, actor="web"):
        seen.append(REAL_COMMAND(t, role, url, stop, actor))
        return ["sleep", "30"]
    monkeypatch.setattr(crun, "command", command)
    return seen


def test_start_status_stop_and_kill(cfg, site, sleeper):
    st = crun.start(cfg, site, role="logout", url="", actor="admin")
    try:
        assert "--stop-file" in sleeper[0] and sleeper[0][sleeper[0].index("--role") + 1] == "logout"
        assert sleeper[0][sleeper[0].index("--actor") + 1] == "admin"
        cur = crun.status(cfg, site)
        assert cur["running"] and cur["role"] == "logout" and cur["pid"] == st["pid"]
        assert "started" in cur["log"] and "display" in cur["log"]
        with pytest.raises(crun.CaptureRunError):
            crun.start(cfg, site, role="user", url="", actor="admin")      # one at a time
        crun.request_stop(cfg, site, "save")
        assert (crun.folder(cfg, site) / "stop").read_text() == "save"
        assert crun.status(cfg, site)["stop_request"] == "save" and not crun.status(cfg, site)["can_kill"]
    finally:
        crun.kill(cfg, site)
    for _ in range(50):
        if not crun.status(cfg, site)["running"]:
            break
        time.sleep(0.1)
    assert not crun.status(cfg, site)["running"]
    with pytest.raises(crun.CaptureRunError):
        crun.request_stop(cfg, site, "save")


def test_display_env(cfg, monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    assert crun.display_env(cfg)["DISPLAY"] == ":0"
    monkeypatch.setenv("DISPLAY", ":1")
    assert crun.display_env(cfg)["DISPLAY"] == ":1"


def test_wait_for_stop_file(tmp_path):
    stop = tmp_path / "stop"
    threading.Timer(0.2, lambda: stop.write_text("save")).start()
    t0 = time.monotonic()
    crun.wait_for_stop_file(stop, poll=0.05)()
    assert stop.exists() and time.monotonic() - t0 < 5


def _fake_drive(url, har_path, state_path, *, headless, on_request, wait, proxy=""):
    on_request(url)
    wait()
    har_path.write_text(json.dumps({"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": url, "cookies": [], "headers": []}, "response": {"headers": []}}]}}))


@pytest.mark.parametrize("how", ["save", "discard"])
def test_cli_capture_with_stop_file(cfg, db, site, monkeypatch, tmp_path, how):
    monkeypatch.setattr(cli, "_cfg", lambda: cfg)
    monkeypatch.setattr(cap, "_drive", _fake_drive)
    stop = tmp_path / "stop"
    threading.Timer(0.3, lambda: stop.write_text(how)).start()
    rc = cli.main(["capture", "www.example.com", "--role", "logout", "--stop-file", str(stop), "--actor", "alice"])
    ver = evmod.Store(cfg, db).load("www.example.com", "har-logout")
    if how == "save":
        assert rc == 0 and ver and ver.items[0].file.endswith(".har")
    else:
        assert rc == 2 and ver is None


def post(client, path, **data):
    data["csrf"] = csrf_of(client)
    return client.post(path, data=data)


def test_web_capture_page(admin_client, guest_client, cfg, site, sleeper):
    page = admin_client.get("/t/www.example.com/tools/capture?role=timeout").get_data(as_text=True)
    assert "Start capture" in page and 'value="timeout" id="role-timeout" checked' in page
    # the walk checklist (so testers do not have to recapture) covers the HAR-reading tests
    assert "While you walk" in page and "wstg01" in page
    assert "state-changing" in page and "search box" in page and "log out in this walk" in page
    assert "Browser capture" in admin_client.get("/t/www.example.com/tools").get_data(as_text=True)
    assert "Start capture" not in guest_client.get("/t/www.example.com/tools/capture").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/tools/capture/start", role="user").status_code == 403
    # out-of-scope start URL and a bad role are refused
    post(admin_client, "/t/www.example.com/tools/capture/start", role="user", url="https://evil.example.net/")
    post(admin_client, "/t/www.example.com/tools/capture/start", role="a b")
    assert crun.status(cfg, site) is None and not sleeper
    r = post(admin_client, "/t/www.example.com/tools/capture/start", role="user")
    assert r.status_code == 302
    try:
        page = admin_client.get("/t/www.example.com/tools/capture").get_data(as_text=True)
        assert "Capture running" in page and "Stop and save" in page and 'http-equiv="refresh"' in page
        post(admin_client, "/t/www.example.com/tools/capture/stop", how="save")
        page = admin_client.get("/t/www.example.com/tools/capture").get_data(as_text=True)
        assert "Stop requested (save)" in page and ">Stop and save</button>" not in page
    finally:
        crun.kill(cfg, site)


def test_links_to_the_capture_tool(admin_client, site):
    page = admin_client.get("/t/www.example.com/evidence/har-logout").get_data(as_text=True)
    assert "/t/www.example.com/tools/capture?role=logout" in page
    page = admin_client.get("/t/www.example.com/auto").get_data(as_text=True)
    assert "/t/www.example.com/tools/capture?role=" in page
