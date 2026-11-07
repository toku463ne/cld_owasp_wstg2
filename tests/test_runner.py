"""Runner tests: a synthetic catalog with harmless local commands only."""

import os
import sys
import time

import pytest

from wstg import catalog as catmod
from wstg import evidence as evmod
from wstg import runner as rmod
from wstg import targets as tm

PY = sys.executable


def ev(eid, argv, level="light", passive=True, **kw):
    return catmod.Evidence(id=eid, title=eid, target_type="fqdn", kind="auto", level=level, passive=passive,
                           argv=tuple(argv), **kw)


@pytest.fixture
def site(db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443", base_url="https://www.example.com",
                    authorization_ref="Contract 2026-001", valid_from="2000-01-01", valid_until="2099-12-31",
                    actor="test")
    return t


def make(cfg, db, *evs):
    cat = catmod.Catalog(wstg_version="4.2", tests={}, evidence={e.id: e for e in evs})
    store = evmod.Store(cfg, db)
    return rmod.Runner(cfg, db, cat, store), store


def run(r, t, mode="light"):
    job = rmod.enqueue(r.db, r.cat, t, mode, "test")
    assert r.claim() == job
    r.run_job(job)
    return {i["evidence_id"]: i for i in rmod.job_items(r.db, job)}


def test_light_mode_collects_and_resumes(cfg, db, site):
    r, store = make(cfg, db,
                    ev("hello", [PY, "-c", "import sys; print('host {fqdn}'); open(sys.argv[1], 'w').write('x')",
                                 "{out}/extra.txt"], files=("extra.txt",)),
                    ev("slow", [PY, "-c", "print(1)"], level="full"))
    items = run(r, site)
    assert list(items) == ["hello"] and items["hello"]["status"] == "complete"
    v = store.load(site.name, "hello")
    assert (v.path / "stdout.txt").read_text() == "host www.example.com\n"
    assert {i.file for i in v.items} == {"stdout.txt", "extra.txt"}
    assert v.meta["argv"][0] == PY and v.meta["exit_code"] == 0
    # second run in full mode: hello is skipped, slow runs
    items = run(r, site, "full")
    assert items["hello"]["status"] == "skipped" and items["slow"]["status"] == "complete"
    assert [h["version"] for h in store.history(site, "hello")] == [1]


def test_failures_are_never_complete(cfg, db, site):
    r, store = make(cfg, db,
                    ev("exit3", [PY, "-c", "import sys; print('partial'); sys.exit(3)"]),
                    ev("nofile", [PY, "-c", "print(1)"], files=("expected.json",)),
                    ev("ok8", [PY, "-c", "import sys; sys.exit(8)"], ok_exit_codes=(0, 8)),
                    ev("slowpoke", [PY, "-c", "import time; time.sleep(30)"], timeout=1),
                    ev("notool", ["wstg-no-such-tool-xyz", "{fqdn}"]))
    items = run(r, site)
    assert items["exit3"]["status"] == "failed" and items["exit3"]["message"] == "exit code 3"
    assert items["nofile"]["message"] == "missing output: expected.json"
    assert items["ok8"]["status"] == "complete"
    assert "timed out" in items["slowpoke"]["message"]
    assert "tool not installed" in items["notool"]["message"]
    for eid in ("exit3", "nofile", "slowpoke"):
        assert store.load(site.name, eid) is None                       # no latest
        assert store.history(site, eid)[0]["status"] == "failed"        # but kept for review
    # a failed collection is tried again next time
    items = run(r, site)
    assert items["exit3"]["status"] == "failed" and items["ok8"]["status"] == "skipped"


def test_scope_is_checked_before_running(cfg, db, site, tmp_path):
    marker = tmp_path / "ran"
    r, store = make(cfg, db,
                    ev("outside", ["touch", str(marker), "https://evil.example.org/"], passive=False),
                    ev("inside", [PY, "-c", "print('ok')", "{base_url}/"], passive=False),
                    ev("badport", [PY, "-c", "print('ok')", "https://www.example.com:8080/"], passive=False))
    items = run(r, site)
    assert items["outside"]["status"] == "refused" and "not in the scope" in items["outside"]["message"]
    assert items["badport"]["status"] == "refused" and "port 8080" in items["badport"]["message"]
    assert items["inside"]["status"] == "complete"
    assert not marker.exists()
    assert store.history(site, "outside") == []

    # queueing needs a valid scope record
    r2, _ = make(cfg, db, ev("again", [PY, "-c", "print(1)"]))
    job = rmod.enqueue(db, r2.cat, site, "light", "test")
    # ... and it is checked again right before each command (it may expire meanwhile)
    tm.update_scope(db, site, allowed_hosts="www.example.com", allowed_ports="443",
                    base_url="https://www.example.com", authorization_ref="", valid_from="", valid_until="",
                    actor="test")
    assert r2.claim() == job
    r2.run_job(job)
    items = {i["evidence_id"]: i for i in rmod.job_items(db, job)}
    assert items["again"]["status"] == "refused" and "no authorization" in items["again"]["message"]
    with pytest.raises(rmod.RunError, match="set the scope record"):
        rmod.enqueue(db, r2.cat, site, "light", "test")


def test_only_one_active_job_and_cancel(cfg, db, site):
    r, store = make(cfg, db, ev("a", [PY, "-c", "print(1)"]), ev("b", [PY, "-c", "print(2)"]))
    job = rmod.enqueue(db, r.cat, site, "light", "test")
    with pytest.raises(rmod.RunError, match="still active"):
        rmod.enqueue(db, r.cat, site, "light", "test")
    rmod.cancel(db, job, "test")
    assert rmod.last_job(db, site)["status"] == "cancelled"
    assert r.claim() is None
    # cancelling a running job stops before the next item
    job = rmod.enqueue(db, r.cat, site, "light", "test")
    assert r.claim() == job
    rmod.cancel(db, job, "test")
    assert r.run_job(job) == "cancelled"
    assert {i["status"] for i in rmod.job_items(db, job)} == {"cancelled"}


def test_recover_marks_interrupted_and_cleans_temp(cfg, db, site):
    r, store = make(cfg, db, ev("a", [PY, "-c", "print(1)"]))
    job = rmod.enqueue(db, r.cat, site, "light", "test")
    r.claim()
    tmp = store.begin(site, "a")
    (tmp / "stdout.txt").write_text("partial")
    assert r.recover() == [job]
    assert rmod.last_job(db, site)["status"] == "interrupted"
    assert not tmp.exists() and store.load(site.name, "a") is None


def test_proxy_and_clean_environment(cfg, db, site, monkeypatch):
    monkeypatch.setenv("https_proxy", "http://198.51.100.1:3128")
    monkeypatch.setenv("SECRET_TOKEN", "do-not-leak")
    r, store = make(cfg, db, ev("env", [PY, "-c", "import os; print(sorted(os.environ))"]))
    run(r, site)
    out = (store.load(site.name, "env").path / "stdout.txt").read_text()
    assert "SECRET_TOKEN" not in out and "https_proxy" not in out
    object.__setattr__(cfg, "http_proxy", "http://127.0.0.1:8080")
    r2, store2 = make(cfg, db, ev("env2", [PY, "-c", "import os; print(os.environ['https_proxy'])"]))
    run(r2, site)
    assert (store2.load(site.name, "env2").path / "stdout.txt").read_text() == "http://127.0.0.1:8080\n"


def test_proxy_args_only_with_a_proxy_and_masked(cfg, db, site):
    argv = [PY, "-c", "import sys; print(sys.argv[1:])", "{proxy_args}", "{base_url}/"]
    e = ev("px", argv, proxy_args=("--proxy", "{proxy_hostport}", "{proxy_url}"))
    r, store = make(cfg, db, e)
    run(r, site)
    v = store.load(site.name, "px")
    assert (v.path / "stdout.txt").read_text() == "['https://www.example.com/']\n"
    assert "{proxy_args}" not in v.meta["argv"]
    # With a proxy (credentials in the URL): the proxy host is not a scope violation,
    # the tool gets the arguments, and the record masks the credentials.
    object.__setattr__(cfg, "http_proxy", "http://user:pw@proxy.example.net:3128")
    r2, store2 = make(cfg, db, ev("px2", argv, proxy_args=e.proxy_args))
    items = run(r2, site)
    assert items["px2"]["status"] == "complete", items["px2"]["message"]
    v = store2.load(site.name, "px2")
    assert (v.path / "stdout.txt").read_text() == (
        "['--proxy', 'proxy.example.net:3128', 'http://user:pw@proxy.example.net:3128', 'https://www.example.com/']\n")
    assert "pw" not in " ".join(v.meta["argv"]) and "pw" not in (v.path / "command.txt").read_text()
    assert "http://***@proxy.example.net:3128" in v.meta["argv"]


def test_direct_tool_failure_mentions_the_proxy(cfg, db, site):
    object.__setattr__(cfg, "http_proxy", "http://127.0.0.1:8080")
    r, store = make(cfg, db, ev("raw", [PY, "-c", "raise SystemExit(1)"], direct=True))
    items = run(r, site)
    assert items["raw"]["status"] == "failed" and "cannot use WSTG_HTTP_PROXY" in items["raw"]["message"]
    assert rmod.last_attempt(db, site, "raw")["status"] == "failed"


def test_missing_tool_is_reported_on_the_evidence_page_data(cfg, db, site):
    r, store = make(cfg, db, ev("nope", ["wstg-no-such-tool-xyz"]))
    items = run(r, site)
    assert items["nope"]["message"] == "tool not installed: wstg-no-such-tool-xyz"
    assert store.load(site.name, "nope") is None
    assert rmod.last_attempt(db, site, "nope")["message"].startswith("tool not installed")


@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    """An `ssh` that runs the remote script locally (records the destination)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "ssh.log"
    (bin_dir / "ssh").write_text(
        "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do last=$1; shift; done; shift\n"
        f"echo \"$last\" >> {log}\nexec sh -c \"$1\"\n")
    (bin_dir / "ssh").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return log


def test_direct_tools_run_on_the_jump_host(cfg, db, site, fake_ssh):
    object.__setattr__(cfg, "http_proxy", "http://127.0.0.1:8080")
    object.__setattr__(cfg, "direct_ssh", "tester@jump.example.net")
    code = ("import os, sys; open(sys.argv[1], 'w').write(os.getcwd());"
            " print('proxy' in ' '.join(os.environ.get(k, '') for k in os.environ if 'proxy' in k))")
    r, store = make(cfg, db,
                    ev("raw", [PY, "-c", code, "{out}/r.txt"], direct=True, files=("r.txt",)),
                    ev("local", [PY, "-c", "print(1)"]),
                    ev("gone", ["wstg-no-such-tool-xyz"], direct=True))
    items = run(r, site)
    assert items["raw"]["status"] == "complete", items["raw"]["message"]
    v = store.load(site.name, "raw")
    remote_dir = (v.path / "r.txt").read_text()
    assert remote_dir.startswith("/tmp/wstg2.") and not os.path.exists(remote_dir)   # cleaned up
    assert v.meta["via"] == "tester@jump.example.net"
    assert (v.path / "command.txt").read_text().startswith("[on tester@jump.example.net] ")
    assert items["local"]["status"] == "complete" and store.load(site.name, "local").meta["via"] == ""
    assert items["gone"]["message"] == "tool not installed on tester@jump.example.net: wstg-no-such-tool-xyz"
    assert store.load(site.name, "gone") is None
    assert "tester@jump.example.net" in fake_ssh.read_text()


def test_jump_host_timeout_stops_the_remote_command(cfg, db, site, fake_ssh):
    object.__setattr__(cfg, "direct_ssh", "jump")
    r, store = make(cfg, db, ev("slow", [PY, "-c", "import time; time.sleep(30)"], direct=True, timeout=2))
    t0 = __import__("time").monotonic()
    items = run(r, site)
    assert items["slow"]["status"] == "failed" and "timed out" in items["slow"]["message"]
    assert __import__("time").monotonic() - t0 < 20


def test_direct_ssh_setting_is_validated(tmp_path):
    from wstg import config
    base = {"WSTG_EVIDENCE_ROOT": str(tmp_path / "e"), "WSTG_DB_PATH": str(tmp_path / "d.db")}
    assert config.load({**base, "WSTG_DIRECT_SSH": "tester@jump.example.net"}, check_repo=False).direct_ssh
    with pytest.raises(config.ConfigError):
        config.load({**base, "WSTG_DIRECT_SSH": "-oProxyCommand=x"}, check_repo=False)


def test_pause_args_only_with_wstg_pause(cfg, db, site):
    argv = [PY, "-c", "import sys; print(sys.argv[1:])", "{pause_args}", "{base_url}/"]
    e = ev("slowly", argv, pause_args=("-p", "{pause}", "-t", "1"))
    r, store = make(cfg, db, e)
    run(r, site)
    assert (store.load(site.name, "slowly").path / "stdout.txt").read_text() == "['https://www.example.com/']\n"
    object.__setattr__(cfg, "pause", 2)
    r2, store2 = make(cfg, db, ev("slowly2", argv, pause_args=e.pause_args))
    run(r2, site)
    v = store2.load(site.name, "slowly2")
    assert (v.path / "stdout.txt").read_text() == "['-p', '2', '-t', '1', 'https://www.example.com/']\n"
    assert v.meta["pause"] == 2


def test_stopped_early_is_never_complete(cfg, db, site):
    r, store = make(cfg, db, ev("capped", [PY, "-c", "print('+ ERROR: Host maximum execution time of 60 seconds reached')"],
                                incomplete_if=("maximum execution time",)))
    items = run(r, site)
    assert items["capped"]["status"] == "failed" and "stopped early" in items["capped"]["message"]
    assert store.load(site.name, "capped") is None


def test_pause_setting_is_validated(tmp_path):
    from wstg import config
    base = {"WSTG_EVIDENCE_ROOT": str(tmp_path / "e"), "WSTG_DB_PATH": str(tmp_path / "d.db")}
    assert config.load({**base, "WSTG_PAUSE": "2"}, check_repo=False).pause == 2
    assert config.load(base, check_repo=False).pause == 0
    for bad in ("-1", "61", "x"):
        with pytest.raises(config.ConfigError):
            config.load({**base, "WSTG_PAUSE": bad}, check_repo=False)


def test_stop_item_kills_only_that_command_and_goes_on(cfg, db, site):
    import threading
    r, store = make(cfg, db, ev("slow", [PY, "-c", "import time; print('started', flush=True); time.sleep(60)"], timeout=120),
                    ev("next", [PY, "-c", "print('ok')"]))
    job = rmod.enqueue(db, r.cat, site, "light", "test")
    assert r.claim() == job
    assert not rmod.stop_item(db, job, 1, "test")          # nothing running yet
    th = threading.Thread(target=r.run_job, args=(job,))
    th.start()
    deadline = time.monotonic() + 20
    while not rmod.stop_item(db, job, 1, "test"):
        assert time.monotonic() < deadline
        time.sleep(0.2)
    th.join(30)
    assert not th.is_alive()
    items = {i["evidence_id"]: i for i in rmod.job_items(db, job)}
    assert items["slow"]["status"] == "cancelled" and "stopped by a tester" in items["slow"]["message"]
    assert items["next"]["status"] == "complete"
    assert rmod.last_job(db, site)["status"] == "done"
    # the stopped evidence is kept as a failed version, never complete
    assert store.load(site.name, "slow") is None
    assert rmod.last_attempt(db, site, "slow")["status"] == "cancelled"
