"""Start and stop a batch `wstg-forge` run from the web (Tools tab > Parameter forging,
WSTG-BUSL-02 step 2).

Forging every selected request with every parameter can be many state-changing requests
and, with WSTG_PAUSE, run for a long time, so a batch runs as a background process on the
tool's host, like Browser capture and Padding oracle decrypt: the web app starts it, the
page shows the progress, and *Stop* writes a stop file the command checks between requests.
One batch per target at a time. A single request can still be sent synchronously from the
page; this is only for the "send all selected" batch.

State lives in `<evidence root>/<target>/_forge/`: state.json, forge.log, stop.
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
from .capture_run import _alive
from .config import Config

FOLDER = "_forge"
KILL_AFTER = 60


class ForgeRunError(Exception):
    pass


def folder(cfg: Config, t: tmod.Target) -> Path:
    return tmod.evidence_dir(cfg, t) / FOLDER


def _exe() -> list[str]:
    exe = Path(sys.executable).with_name("wstg-forge")
    return [str(exe)] if exe.is_file() else [sys.executable, "-m", "wstg.forge"]


def _ev_latest(cfg: Config, t: tmod.Target, eid: str) -> str | None:
    link = tmod.evidence_dir(cfg, t) / eid / "latest"
    return str(link.resolve()) if link.is_dir() else None


def command(cfg: Config, t: tmod.Target, base_url: str, requests: list[int],
            params: list[str], stop_file: Path) -> list[str]:
    argv = _exe() + ["--base", base_url.rstrip("/") + "/", "--agree", "--stop-file", str(stop_file)]
    har = _ev_latest(cfg, t, "har-browse")
    katana = _ev_latest(cfg, t, "katana-crawl")
    if har:
        argv += ["--har", har]
    if katana:
        argv += ["--katana", katana]
    if requests:
        for n in requests:
            argv += ["--request", str(n)]
    else:
        argv.append("--all")
    for p in params:
        argv += ["--param", p]
    if cfg.pause:
        argv += ["--pause", str(cfg.pause)]
    return argv


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
        lines = (d / "forge.log").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    st["log"] = "\n".join(lines[-200:])
    st["elapsed"] = int(time.time() - st.get("started_ts", time.time()))
    st["finished"] = bool(not st["running"] and lines)
    return st


def start(cfg: Config, t: tmod.Target, *, base_url: str, requests: list[int], params: list[str],
          actor: str, popen=subprocess.Popen) -> dict:
    cur = status(cfg, t)
    if cur and cur["running"]:
        raise ForgeRunError(f"a forge batch of {t.name} is already running")
    if not params:
        raise ForgeRunError("give at least one parameter")
    d = folder(cfg, t)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    (d / "stop").unlink(missing_ok=True)
    log = d / "forge.log"
    argv = command(cfg, t, base_url, requests, params, d / "stop")
    label = f"{len(requests)} request(s)" if requests else "all requests"
    with open(log, "w") as fh:
        fh.write(f"# started {dbmod.utcnow()} by {actor}: {label}, {len(params)} parameter(s)\n")
        fh.flush()
        proc = popen(argv, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                     start_new_session=True, close_fds=True)
    st = {"pid": proc.pid, "requests": requests, "params": params, "label": label, "actor": actor,
          "base_url": base_url, "started": dbmod.utcnow(), "started_ts": time.time()}
    (d / "state.json").write_text(json.dumps(st))
    return st


def request_stop(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise ForgeRunError("no forge batch is running")
    (folder(cfg, t) / "stop").write_text("stop")


def kill(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise ForgeRunError("no forge batch is running")
    try:
        os.killpg(int(cur["pid"]), signal.SIGKILL)
    except ProcessLookupError:
        pass
    with open(folder(cfg, t) / "forge.log", "a") as fh:
        fh.write(f"# killed {dbmod.utcnow()}\n")


def result_text(cfg: Config, t: tmod.Target) -> str:
    st = status(cfg, t) or {}
    head = f"# wstg forge batch: {st.get('label', '')}, parameters {', '.join(st.get('params', []))}\n"
    text = head + st.get("log", "") + "\n"
    room = evmod.MAX_TEXT_BYTES - 200
    return text if len(text.encode()) <= room else text[:room] + "\n... truncated\n"
