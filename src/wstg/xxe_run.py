"""Start and stop a background `wstg-xxe` probe from the web (Tools tab > XML injection /
XXE, WSTG-INPV-07 step 2).

Probing each XML request sends several active payloads and, with WSTG_PAUSE, can run for a
while, so it runs as a background process on the tool's host like the other probe tools:
the web app starts it, the page shows the progress, and *Stop* writes a stop file the
command checks between requests. One run per target at a time.

State lives in `<evidence root>/<target>/_xxe/`: state.json, xxe.log, stop, added.
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

FOLDER = "_xxe"
EVIDENCE = "xml-injection-tests"
KILL_AFTER = 60


class XxeRunError(Exception):
    pass


def folder(cfg: Config, t: tmod.Target) -> Path:
    return tmod.evidence_dir(cfg, t) / FOLDER


def _exe() -> list[str]:
    exe = Path(sys.executable).with_name("wstg-xxe")
    return [str(exe)] if exe.is_file() else [sys.executable, "-m", "wstg.xxe"]


def _ev_latest(cfg: Config, t: tmod.Target, eid: str) -> str | None:
    link = tmod.evidence_dir(cfg, t) / eid / "latest"
    return str(link.resolve()) if link.is_dir() else None


def _base_args(cfg: Config, t: tmod.Target, base_url: str) -> list[str]:
    argv = _exe() + ["--base", base_url.rstrip("/") + "/"]
    katana = _ev_latest(cfg, t, "katana-crawl")
    har = _ev_latest(cfg, t, "har-browse")
    if katana:
        argv += ["--katana", katana]
    if har:
        argv += ["--har", har]
    return argv


def command(cfg: Config, t: tmod.Target, base_url: str, requests: list[int], stop_file: Path) -> list[str]:
    argv = _base_args(cfg, t, base_url) + ["--agree", "--stop-file", str(stop_file)]
    if requests:
        for n in requests:
            argv += ["--request", str(n)]
    else:
        argv.append("--all")
    if cfg.pause:
        argv += ["--pause", str(cfg.pause)]
    return argv


def candidates(cfg: Config, t: tmod.Target, base_url: str) -> list[dict]:
    """The candidate XML requests (no request sent)."""
    argv = _base_args(cfg, t, base_url) + ["--list"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise XxeRunError(str(e)) from e
    cands = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 5 and parts[0].isdigit():
            cands.append({"n": int(parts[0]), "method": parts[1], "template": parts[2],
                          "kind": parts[3], "name": parts[4],
                          "role": (parts[5].strip("()") if len(parts) > 5 else "")})
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
        lines = (d / "xxe.log").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    st["log"] = "\n".join(lines[-200:])
    st["elapsed"] = int(time.time() - st.get("started_ts", time.time()))
    st["finished"] = bool(not st["running"] and lines)
    st["added"] = (d / "added").is_file()
    return st


def mark_added(cfg: Config, t: tmod.Target) -> None:
    (folder(cfg, t) / "added").write_text(dbmod.utcnow())


def start(cfg: Config, t: tmod.Target, *, base_url: str, requests: list[int], actor: str,
          discard: bool = False, popen=subprocess.Popen) -> dict:
    cur = status(cfg, t)
    if cur and cur["running"]:
        raise XxeRunError(f"an XXE probe of {t.name} is already running")
    if cur and cur.get("finished") and not cur.get("added") and not discard:
        raise XxeRunError(f"the previous result is not saved yet. Add it to {EVIDENCE} first, "
                          "or tick 'discard the previous result' to overwrite it.")
    d = folder(cfg, t)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    (d / "stop").unlink(missing_ok=True)
    (d / "added").unlink(missing_ok=True)
    log = d / "xxe.log"
    argv = command(cfg, t, base_url, requests, d / "stop")
    label = f"{len(requests)} XML request(s)" if requests else "all XML requests"
    with open(log, "w") as fh:
        fh.write(f"# started {dbmod.utcnow()} by {actor}: {label}\n")
        fh.flush()
        proc = popen(argv, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                     env=proxy_env(cfg), start_new_session=True, close_fds=True)
    st = {"pid": proc.pid, "requests": requests, "label": label, "actor": actor,
          "base_url": base_url, "started": dbmod.utcnow(), "started_ts": time.time()}
    (d / "state.json").write_text(json.dumps(st))
    return st


def request_stop(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise XxeRunError("no XXE probe is running")
    (folder(cfg, t) / "stop").write_text("stop")


def kill(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise XxeRunError("no XXE probe is running")
    try:
        os.killpg(int(cur["pid"]), signal.SIGKILL)
    except ProcessLookupError:
        pass
    with open(folder(cfg, t) / "xxe.log", "a") as fh:
        fh.write(f"# killed {dbmod.utcnow()}\n")


def result_text(cfg: Config, t: tmod.Target) -> str:
    st = status(cfg, t) or {}
    head = f"# wstg XML injection / XXE probe: {st.get('label', '')}\n"
    text = head + st.get("log", "") + "\n"
    room = evmod.MAX_TEXT_BYTES - 200
    return text if len(text.encode()) <= room else text[:room] + "\n... truncated\n"
