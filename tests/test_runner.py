"""Runner tests: a synthetic catalog with harmless local commands only."""

import os
import sys

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
