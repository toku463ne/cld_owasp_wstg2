"""Start and stop a background `wstg-inject` probe from the web (Tools tab > Injection
probe, the WSTG-INPV active-probe steps).

Probing every parameter with a pack's payloads is many active requests and, with
WSTG_PAUSE, can run for a long time, so it runs as a background process on the tool's host
like the forge and XSS-confirm tools: the web app starts it, the page shows the progress,
and *Stop* writes a stop file the command checks between parameters. One run per (target,
pack) at a time.

State lives in `<evidence root>/<target>/_inject/<pack>/`: state.json, inject.log, stop,
added.
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
from . import inject as imod
from . import targets as tmod
from .capture_run import _alive, proxy_env
from .config import Config

KILL_AFTER = 60

# Which manual evidence each pack's result is added to.
PACK_EVIDENCE = {"sqli": "sqli-tests", "ssti": "ssti-tests", "xpath": "xpath-injection-tests",
                 "ldap": "ldap-injection-tests", "cmd": "command-injection-tests"}


class InjectRunError(Exception):
    pass


def _pack(key: str) -> imod.Pack:
    p = imod.PACKS.get(key)
    if not p:
        raise InjectRunError(f"unknown pack {key!r}")
    return p


def folder(cfg: Config, t: tmod.Target, pack: str) -> Path:
    return tmod.evidence_dir(cfg, t) / "_inject" / pack


def _exe() -> list[str]:
    exe = Path(sys.executable).with_name("wstg-inject")
    return [str(exe)] if exe.is_file() else [sys.executable, "-m", "wstg.inject"]


def _ev_latest(cfg: Config, t: tmod.Target, eid: str) -> str | None:
    link = tmod.evidence_dir(cfg, t) / eid / "latest"
    return str(link.resolve()) if link.is_dir() else None


def _base_args(cfg: Config, t: tmod.Target, base_url: str, pack: str) -> list[str]:
    argv = _exe() + ["--pack", pack, "--base", base_url.rstrip("/") + "/"]
    katana = _ev_latest(cfg, t, "katana-crawl")
    har = _ev_latest(cfg, t, "har-browse")
    if katana:
        argv += ["--katana", katana]
    if har:
        argv += ["--har", har]
    return argv


def command(cfg: Config, t: tmod.Target, base_url: str, pack: str, requests: list[int],
            stop_file: Path) -> list[str]:
    argv = _base_args(cfg, t, base_url, pack) + ["--agree", "--stop-file", str(stop_file)]
    if requests:
        for n in requests:
            argv += ["--request", str(n)]
    else:
        argv.append("--all")
    if cfg.pause:
        argv += ["--pause", str(cfg.pause)]
    return argv


def candidates(cfg: Config, t: tmod.Target, base_url: str, pack: str) -> list[dict]:
    """The candidate parameters for this pack (no request sent)."""
    _pack(pack)
    argv = _base_args(cfg, t, base_url, pack) + ["--list"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise InjectRunError(str(e)) from e
    cands = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0].isdigit():
            cands.append({"n": int(parts[0]), "method": parts[1], "template": parts[2],
                          "param": parts[3].lstrip("?"), "role": parts[4] if len(parts) > 4 else ""})
    return cands


def status(cfg: Config, t: tmod.Target, pack: str) -> dict | None:
    d = folder(cfg, t, pack)
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
        lines = (d / "inject.log").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    st["log"] = "\n".join(lines[-200:])
    st["elapsed"] = int(time.time() - st.get("started_ts", time.time()))
    st["finished"] = bool(not st["running"] and lines)
    st["added"] = (d / "added").is_file()
    return st


def mark_added(cfg: Config, t: tmod.Target, pack: str) -> None:
    (folder(cfg, t, pack) / "added").write_text(dbmod.utcnow())


def start(cfg: Config, t: tmod.Target, *, base_url: str, pack: str, requests: list[int],
          actor: str, discard: bool = False, popen=subprocess.Popen) -> dict:
    _pack(pack)
    cur = status(cfg, t, pack)
    if cur and cur["running"]:
        raise InjectRunError(f"a {pack} probe of {t.name} is already running")
    if cur and cur.get("finished") and not cur.get("added") and not discard:
        raise InjectRunError(f"the previous {pack} result is not saved yet. Add it to "
                             f"{PACK_EVIDENCE.get(pack, pack)} first, or tick 'discard the previous result'.")
    d = folder(cfg, t, pack)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    (d / "stop").unlink(missing_ok=True)
    (d / "added").unlink(missing_ok=True)
    log = d / "inject.log"
    argv = command(cfg, t, base_url, pack, requests, d / "stop")
    label = f"{len(requests)} parameter(s)" if requests else "all parameters"
    with open(log, "w") as fh:
        fh.write(f"# started {dbmod.utcnow()} by {actor}: {pack} probe, {label}\n")
        fh.flush()
        proc = popen(argv, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                     env=proxy_env(cfg), start_new_session=True, close_fds=True)
    st = {"pid": proc.pid, "pack": pack, "requests": requests, "label": label, "actor": actor,
          "base_url": base_url, "started": dbmod.utcnow(), "started_ts": time.time()}
    (d / "state.json").write_text(json.dumps(st))
    return st


def request_stop(cfg: Config, t: tmod.Target, pack: str) -> None:
    cur = status(cfg, t, pack)
    if not cur or not cur["running"]:
        raise InjectRunError("no probe is running")
    (folder(cfg, t, pack) / "stop").write_text("stop")


def kill(cfg: Config, t: tmod.Target, pack: str) -> None:
    cur = status(cfg, t, pack)
    if not cur or not cur["running"]:
        raise InjectRunError("no probe is running")
    try:
        os.killpg(int(cur["pid"]), signal.SIGKILL)
    except ProcessLookupError:
        pass
    with open(folder(cfg, t, pack) / "inject.log", "a") as fh:
        fh.write(f"# killed {dbmod.utcnow()}\n")


def result_text(cfg: Config, t: tmod.Target, pack: str) -> str:
    st = status(cfg, t, pack) or {}
    head = f"# wstg {pack} injection probe: {st.get('label', '')}\n"
    text = head + st.get("log", "") + "\n"
    room = evmod.MAX_TEXT_BYTES - 200
    return text if len(text.encode()) <= room else text[:room] + "\n... truncated\n"
