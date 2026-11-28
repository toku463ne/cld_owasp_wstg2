"""Start and stop a background `wstg-raw` probe from the web (Tools tab > Raw request probe,
WSTG-INPV-16 step 2).

The raw/malformed battery can run a while (with WSTG_PAUSE, one request at a time), so it
runs as a background process on the tool's host like the other probe tools: the web app
starts it, the page shows the progress, and *Stop* writes a stop file the command checks
between items. One run per target at a time. The oversized-header step is only sent when
the tester ticks the extra box (it can destabilise the parser).

State lives in `<evidence root>/<target>/_raw/`: state.json, raw.log, stop, added.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import db as dbmod
from . import evidence as evmod
from . import targets as tmod
from .capture_run import _alive, proxy_env
from .config import Config

FOLDER = "_raw"
EVIDENCE = "raw-request-tests"
KILL_AFTER = 60


class RawRunError(Exception):
    pass


def folder(cfg: Config, t: tmod.Target) -> Path:
    return tmod.evidence_dir(cfg, t) / FOLDER


def _exe() -> list[str]:
    exe = Path(sys.executable).with_name("wstg-raw")
    return [str(exe)] if exe.is_file() else [sys.executable, "-m", "wstg.rawreq"]


def _ev_latest(cfg: Config, t: tmod.Target, eid: str) -> str | None:
    link = tmod.evidence_dir(cfg, t) / eid / "latest"
    return str(link.resolve()) if link.is_dir() else None


def _base_args(cfg: Config, t: tmod.Target, base_url: str, paths: list[str]) -> list[str]:
    argv = _exe() + ["--base", base_url.rstrip("/") + "/"]
    katana = _ev_latest(cfg, t, "katana-crawl")
    if katana:
        argv += ["--katana", katana]
    for p in paths:
        argv += ["--path", p]
    return argv


def command(cfg: Config, t: tmod.Target, base_url: str, paths: list[str], requests: list[int],
            stop_file: Path, *, oversized: bool = False) -> list[str]:
    argv = _base_args(cfg, t, base_url, paths) + ["--agree", "--stop-file", str(stop_file)]
    if oversized:
        argv.append("--agree-oversized")
    if requests:
        for n in requests:
            argv += ["--request", str(n)]
    else:
        argv.append("--all")
    if cfg.pause:
        argv += ["--pause", str(cfg.pause)]
    return argv


def candidates(cfg: Config, t: tmod.Target, base_url: str, paths: list[str]) -> list[dict]:
    """The candidate items (no request sent): the normalisation paths plus the parser battery."""
    argv = _base_args(cfg, t, base_url, paths) + ["--list"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise RawRunError(str(e)) from e
    cands = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0].isdigit():
            cands.append({"n": int(parts[0]), "method": parts[1], "path": parts[2],
                          "kind": parts[3].strip("()")})
    return cands


def status(cfg: Config, t: tmod.Target) -> dict | None:
    d = folder(cfg, t)
    try:
        st = json.loads((d / "state.json").read_text())
    except (OSError, ValueError):
        return None
    st["running"] = _alive(int(st.get("pid") or 0)) if st.get("pid") else False
    stop = d / "stop"
    st["stop_request"] = stop.is_file()
    st["stop_age"] = time.time() - stop.stat().st_mtime if stop.is_file() else 0
    st["can_kill"] = st["running"] and st["stop_request"] and st["stop_age"] > KILL_AFTER
    try:
        lines = (d / "raw.log").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    st["log"] = "\n".join(lines[-200:])
    st["elapsed"] = int(time.time() - st.get("started_ts", time.time()))
    st["finished"] = bool(not st["running"] and lines)
    st["added"] = (d / "added").is_file()
    return st


def mark_added(cfg: Config, t: tmod.Target) -> None:
    (folder(cfg, t) / "added").write_text(dbmod.utcnow())


def start(cfg: Config, t: tmod.Target, *, base_url: str, paths: list[str], requests: list[int],
          actor: str, oversized: bool = False, discard: bool = False, popen=subprocess.Popen) -> dict:
    cur = status(cfg, t)
    if cur and cur["running"]:
        raise RawRunError(f"a raw request probe of {t.name} is already running")
    if cur and cur.get("finished") and not cur.get("added") and not discard:
        raise RawRunError(f"the previous result is not saved yet. Add it to {EVIDENCE} first, "
                          "or tick 'discard the previous result' to overwrite it.")
    d = folder(cfg, t)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    (d / "stop").unlink(missing_ok=True)
    (d / "added").unlink(missing_ok=True)
    log = d / "raw.log"
    argv = command(cfg, t, base_url, paths, requests, d / "stop", oversized=oversized)
    label = (f"{len(requests)} item(s)" if requests else "all items") + (" + oversized" if oversized else "")
    with open(log, "w") as fh:
        fh.write(f"# started {dbmod.utcnow()} by {actor}: {label}\n")
        fh.flush()
        proc = popen(argv, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                     env=proxy_env(cfg), start_new_session=True, close_fds=True)
    st = {"pid": proc.pid, "requests": requests, "paths": paths, "oversized": oversized,
          "label": label, "actor": actor, "base_url": base_url,
          "started": dbmod.utcnow(), "started_ts": time.time()}
    (d / "state.json").write_text(json.dumps(st))
    return st


def request_stop(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise RawRunError("no raw request probe is running")
    (folder(cfg, t) / "stop").write_text("stop")


def kill(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise RawRunError("no raw request probe is running")
    try:
        os.killpg(int(cur["pid"]), signal.SIGKILL)
    except ProcessLookupError:
        pass
    with open(folder(cfg, t) / "raw.log", "a") as fh:
        fh.write(f"# killed {dbmod.utcnow()}\n")


def result_text(cfg: Config, t: tmod.Target) -> str:
    st = status(cfg, t) or {}
    head = f"# wstg raw/malformed request probe: {st.get('label', '')}\n"
    text = head + st.get("log", "") + "\n"
    room = evmod.MAX_TEXT_BYTES - 200
    return text if len(text.encode()) <= room else text[:room] + "\n... truncated\n"
