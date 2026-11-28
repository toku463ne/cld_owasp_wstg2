"""Start and stop a headless `wstg-reflect confirm` run from the web (Tools tab >
Reflected XSS confirm, WSTG-INPV-01 step 4).

Confirming a REFLECTED-UNENCODED parameter launches a headless browser per parameter and
sends a real (benign sentinel) payload, so it can take a while and may trip a WAF. It runs
as a background process on the tool's host, like the forge and decrypt tools: the web app
starts it, the page shows the progress, and *Stop* writes a stop file the command checks
between parameters. One run per target at a time.

State lives in `<evidence root>/<target>/_xss/`: state.json, xss.log, stop, added, and the
screenshots (xss-*.png).
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

FOLDER = "_xss"
KILL_AFTER = 60


class XssRunError(Exception):
    pass


def folder(cfg: Config, t: tmod.Target) -> Path:
    return tmod.evidence_dir(cfg, t) / FOLDER


def _exe() -> list[str]:
    exe = Path(sys.executable).with_name("wstg-reflect")
    return [str(exe)] if exe.is_file() else [sys.executable, "-m", "wstg.reflect"]


def _ev_latest(cfg: Config, t: tmod.Target, eid: str) -> str | None:
    link = tmod.evidence_dir(cfg, t) / eid / "latest"
    return str(link.resolve()) if link.is_dir() else None


def command(cfg: Config, t: tmod.Target, base_url: str, candidates: list[int], stop_file: Path,
            out: Path) -> list[str]:
    argv = _exe() + ["confirm", "--base", base_url.rstrip("/") + "/", "--agree",
                     "--out", str(out), "--stop-file", str(stop_file)]
    reflect = _ev_latest(cfg, t, "reflection-check")
    har = _ev_latest(cfg, t, "har-browse")
    if reflect:
        argv += ["--reflect", reflect]
    if har:
        argv += ["--har", har]
    if candidates:
        for n in candidates:
            argv += ["--candidate", str(n)]
    else:
        argv.append("--all")
    if cfg.pause:
        argv += ["--pause", str(cfg.pause)]
    return argv


def candidates(cfg: Config, t: tmod.Target, base_url: str) -> list[dict]:
    """The REFLECTED-UNENCODED parameters from reflection-check (no request sent)."""
    reflect = _ev_latest(cfg, t, "reflection-check")
    if not reflect:
        return []
    argv = _exe() + ["confirm", "--base", base_url.rstrip("/") + "/", "--reflect", reflect, "--list"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise XssRunError(str(e)) from e
    cands = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0].isdigit():
            cands.append({"n": int(parts[0]), "param": parts[1], "where": parts[2], "url": parts[3]})
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
        lines = (d / "xss.log").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    st["log"] = "\n".join(lines[-200:])
    st["elapsed"] = int(time.time() - st.get("started_ts", time.time()))
    st["finished"] = bool(not st["running"] and lines)
    st["added"] = (d / "added").is_file()
    st["shots"] = sorted(p.name for p in d.glob("xss-*.png")) if d.is_dir() else []
    return st


def mark_added(cfg: Config, t: tmod.Target) -> None:
    (folder(cfg, t) / "added").write_text(dbmod.utcnow())


def start(cfg: Config, t: tmod.Target, *, base_url: str, candidates: list[int], actor: str,
          discard: bool = False, popen=subprocess.Popen) -> dict:
    cur = status(cfg, t)
    if cur and cur["running"]:
        raise XssRunError(f"an XSS confirm of {t.name} is already running")
    if cur and cur.get("finished") and not cur.get("added") and not discard:
        raise XssRunError("the previous result is not saved yet. Add it to xss-reflected-tests first, "
                          "or tick 'discard the previous result' to overwrite it.")
    d = folder(cfg, t)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    for p in list(d.glob("xss-*.png")):
        p.unlink()
    (d / "stop").unlink(missing_ok=True)
    (d / "added").unlink(missing_ok=True)
    log = d / "xss.log"
    argv = command(cfg, t, base_url, candidates, d / "stop", d)
    label = f"{len(candidates)} parameter(s)" if candidates else "all parameters"
    with open(log, "w") as fh:
        fh.write(f"# started {dbmod.utcnow()} by {actor}: {label}\n")
        fh.flush()
        proc = popen(argv, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                     env=proxy_env(cfg), start_new_session=True, close_fds=True)
    st = {"pid": proc.pid, "candidates": candidates, "label": label, "actor": actor,
          "base_url": base_url, "started": dbmod.utcnow(), "started_ts": time.time()}
    (d / "state.json").write_text(json.dumps(st))
    return st


def request_stop(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise XssRunError("no XSS confirm is running")
    (folder(cfg, t) / "stop").write_text("stop")


def kill(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise XssRunError("no XSS confirm is running")
    try:
        os.killpg(int(cur["pid"]), signal.SIGKILL)
    except ProcessLookupError:
        pass
    with open(folder(cfg, t) / "xss.log", "a") as fh:
        fh.write(f"# killed {dbmod.utcnow()}\n")


def result_text(cfg: Config, t: tmod.Target) -> str:
    st = status(cfg, t) or {}
    head = f"# wstg reflected-XSS confirm: {st.get('label', '')}\n"
    text = head + st.get("log", "") + "\n"
    room = evmod.MAX_TEXT_BYTES - 200
    return text if len(text.encode()) <= room else text[:room] + "\n... truncated\n"


def screenshots(cfg: Config, t: tmod.Target) -> list[tuple[bytes, str]]:
    """(png bytes, caption) for each screenshot of the last run, to add as image evidence."""
    d = folder(cfg, t)
    out = []
    for p in sorted(d.glob("xss-*.png")):
        try:
            out.append((p.read_bytes(), p.stem))
        except OSError:
            pass
    return out
