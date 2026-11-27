"""wstg-ffuf-run: resumable chunks of an ffuf word list (a fake ffuf, no network)."""

import json
import os
import stat
import sys

from wstg import catalog as catmod
from wstg import evidence as evmod
from wstg import ffufrun
from wstg import runner as rmod
from wstg import targets as tm

# Stand-in for ffuf: reads -w LIST:FUZZ and -o FILE, answers every word that starts
# with "a" as a hit, and fails (exit 1, no output) on the word in $FAKE_FFUF_FAIL.
# Each call is logged to $FAKE_FFUF_LOG, one line with the words it got.
FAKE = """\
import json, os, sys
a = sys.argv[1:]
wl, kw = a[a.index("-w") + 1].rsplit(":", 1)
out = a[a.index("-o") + 1]
words = open(wl).read().split()
with open(os.environ["FAKE_FFUF_LOG"], "a") as f:
    f.write(" ".join(words) + "\\n")
if os.environ.get("FAKE_FFUF_FAIL") in words:
    sys.exit(1)
res = [{"input": {kw: w}, "url": "https://www.example.com/" + w, "status": 200} for w in words if w.startswith("a")]
json.dump({"commandline": " ".join(sys.argv), "results": res, "config": {"keyword": kw}}, open(out, "w"))
"""


def fake_ffuf(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    f = bindir / "ffuf"
    f.write_text(f"#!{sys.executable}\n" + FAKE)
    f.chmod(f.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    log = tmp_path / "ffuf.log"
    monkeypatch.setenv("FAKE_FFUF_LOG", str(log))
    return log


def words(tmp_path, n=10):
    wl = tmp_path / "words.txt"
    wl.write_text("".join(f"{'a' if i % 2 == 0 else 'b'}{i}\n" for i in range(n)))
    return wl


def cmd(wl, out, *extra):
    return ["ffuf", "-s", "-w", f"{wl}:FUZZ", "-u", "https://www.example.com/FUZZ", "-o", str(out), "-of", "json", *extra]


def test_chunks_merge_into_one_ffuf_json(tmp_path, monkeypatch):
    log = fake_ffuf(tmp_path, monkeypatch)
    out = tmp_path / "out" / "ffuf.json"
    out.parent.mkdir()
    rc = ffufrun.main(["--resume", str(tmp_path / "r"), "--chunk", "4", "--", *cmd(words(tmp_path), out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert [r["input"]["FUZZ"] for r in data["results"]] == ["a0", "a2", "a4", "a6", "a8"]
    assert data["chunks"] == 3 and data["config"] == {"keyword": "FUZZ"}
    assert data["commandline"].startswith("ffuf -s -w ")
    assert len(log.read_text().splitlines()) == 3


def test_a_failed_chunk_resumes_where_it_stopped(tmp_path, monkeypatch, capsys):
    log = fake_ffuf(tmp_path, monkeypatch)
    out, resume, wl = tmp_path / "ffuf.json", tmp_path / "r", words(tmp_path)
    monkeypatch.setenv("FAKE_FFUF_FAIL", "b5")              # in the second chunk (a4 b5 a6 b7)
    assert ffufrun.main(["--resume", str(resume), "--chunk", "4", "--", *cmd(wl, out)]) == 1
    assert not out.exists() and (resume / "chunk-0000.json").is_file()
    assert not list(resume.glob("*.part"))
    assert "1 of 3 chunks are kept" in capsys.readouterr().out
    monkeypatch.delenv("FAKE_FFUF_FAIL")
    log.write_text("")
    # pacing and proxy options may change between runs; the done chunk is still reused
    assert ffufrun.main(["--resume", str(resume), "--chunk", "4", "--", *cmd(wl, out, "-p", "1", "-t", "1")]) == 0
    assert log.read_text().splitlines() == ["a4 b5 a6 b7", "a8 b9"]   # chunk 1 was not sent again
    assert "1 already done" in capsys.readouterr().out
    assert len(json.loads(out.read_text())["results"]) == 5


def test_a_different_scan_starts_again(tmp_path, monkeypatch):
    log = fake_ffuf(tmp_path, monkeypatch)
    out, resume, wl = tmp_path / "ffuf.json", tmp_path / "r", words(tmp_path)
    monkeypatch.setenv("FAKE_FFUF_FAIL", "b5")
    ffufrun.main(["--resume", str(resume), "--chunk", "4", "--", *cmd(wl, out)])
    monkeypatch.delenv("FAKE_FFUF_FAIL")
    log.write_text("")
    assert ffufrun.main(["--resume", str(resume), "--chunk", "4", "--", *cmd(wl, out, "-e", ".bak")]) == 0
    assert len(log.read_text().splitlines()) == 3            # other extensions: nothing reused


def test_usage_errors(tmp_path):
    assert ffufrun.main(["--resume", str(tmp_path / "r"), "--", "ffuf", "-u", "https://www.example.com/FUZZ"]) == 2
    assert ffufrun.main(["--resume", str(tmp_path / "r")]) == 2


def test_runner_keeps_resume_until_complete(cfg, db, tmp_path, monkeypatch):
    log = fake_ffuf(tmp_path, monkeypatch)
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="443", base_url="https://www.example.com",
                    authorization_ref="Contract 2026-001", valid_from="2000-01-01", valid_until="2099-12-31",
                    actor="test")
    wl = words(tmp_path)
    e = catmod.Evidence(id="fz", title="fz", target_type="fqdn", kind="auto", level="full", heavy=True,
                        load_note="n", files=("ffuf.json",),
                        argv=("wstg-ffuf-run", "--resume", "{resume}", "--chunk", "4", "--",
                              "ffuf", "-w", f"{wl}:FUZZ", "-u", "{base_url}/FUZZ", "-o", "{out}/ffuf.json"))
    cat = catmod.Catalog(wstg_version="4.2", tests={}, evidence={"fz": e})
    store = evmod.Store(cfg, db)
    r = rmod.Runner(cfg, db, cat, store)
    monkeypatch.setattr(r, "env", lambda: dict(os.environ))
    resume = store.folder(t.name, "fz") / rmod.RESUME_FOLDER
    monkeypatch.setenv("FAKE_FFUF_FAIL", "b5")
    assert r.collect(t, e).status == "failed"
    assert (resume / "chunk-0000.json").is_file()            # kept for the next run
    monkeypatch.delenv("FAKE_FFUF_FAIL")
    log.write_text("")
    assert r.collect(t, e).status == "complete"
    assert len(log.read_text().splitlines()) == 2            # went on from the second chunk
    assert not resume.exists()                                # gone once stored complete
    assert len(json.loads((store.load(t.name, "fz").path / "ffuf.json").read_text())["results"]) == 5
