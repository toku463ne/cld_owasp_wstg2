"""Start and stop `wstg-cryp padding-decrypt` from the web (Tools tab > Padding oracle
decrypt, WSTG-CRYP-02 step 4).

Confirming a suspected padding oracle takes thousands of requests and runs for a long
time (longer with WSTG_PAUSE), so it runs as a background process on the tool's host,
like Browser capture: the web app starts it, the page shows the progress, and *Stop*
writes a stop file that the command checks between bytes. One decrypt per target at a
time. `candidates()` lists the values without sending anything (`padding-decrypt --list`).

State lives in `<evidence root>/<target>/_decrypt/`: state.json (pid, candidate, start
time, who), decrypt.log (the command's output), stop (the stop file).
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

FOLDER = "_decrypt"
INPUTS = ["http-root-https", "har-browse", "session-token-samples"]
KILL_AFTER = 60          # seconds after a stop request before a kill is offered


class DecryptRunError(Exception):
    pass


def folder(cfg: Config, t: tmod.Target) -> Path:
    return tmod.evidence_dir(cfg, t) / FOLDER


def _exe() -> list[str]:
    exe = Path(sys.executable).with_name("wstg-cryp")
    return [str(exe)] if exe.is_file() else [sys.executable, "-m", "wstg.cryp"]


def _input_args(cfg: Config, t: tmod.Target) -> list[str]:
    """--http-root/--har/--samples pointing at each input's newest complete version
    (left out when the target has no such evidence yet)."""
    flags = {"http-root-https": "--http-root", "har-browse": "--har", "session-token-samples": "--samples"}
    args: list[str] = []
    for eid in INPUTS:
        link = tmod.evidence_dir(cfg, t) / eid / "latest"
        if link.is_dir():
            args += [flags[eid], str(link.resolve())]
    return args


def command(cfg: Config, t: tmod.Target, base_url: str, candidate: int, stop_file: Path) -> list[str]:
    argv = _exe() + ["padding-decrypt", "--base", base_url.rstrip("/") + "/",
                     "--candidate", str(candidate), "--stop-file", str(stop_file)]
    args = _input_args(cfg, t)
    if cfg.pause:
        argv += ["--pause", str(cfg.pause)]
    return argv + args


def candidates(cfg: Config, t: tmod.Target, base_url: str) -> list[dict]:
    """The candidate values (padding-decrypt --list, no request): [{n, label}]. The tester
    runs the step-3 probe to see which are SUSPECTED-ORACLE, then decrypts one here."""
    argv = _exe() + ["padding-decrypt", "--base", base_url.rstrip("/") + "/", "--list"] + _input_args(cfg, t)
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise DecryptRunError(str(e)) from e
    cands = []
    for line in out.splitlines():
        if "\t" in line and line.split("\t", 1)[0].isdigit():
            n, label = line.split("\t", 1)
            cands.append({"n": int(n), "label": label})
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
        lines = (d / "decrypt.log").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    st["log"] = "\n".join(lines[-60:])
    st["elapsed"] = int(time.time() - st.get("started_ts", time.time()))
    # It finished when the process is gone and the log has a final line (recovered block,
    # stop, or error): the page then offers to add the result to the evidence.
    st["finished"] = bool(not st["running"] and lines)
    return st


def start(cfg: Config, t: tmod.Target, *, base_url: str, candidate: int, label: str,
          actor: str, popen=subprocess.Popen) -> dict:
    cur = status(cfg, t)
    if cur and cur["running"]:
        raise DecryptRunError(f"a decrypt of {t.name} is already running (candidate {cur.get('candidate')})")
    if candidate < 1:
        raise DecryptRunError("pick a candidate to decrypt")
    d = folder(cfg, t)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    (d / "stop").unlink(missing_ok=True)
    log = d / "decrypt.log"
    argv = command(cfg, t, base_url, candidate, d / "stop")
    with open(log, "w") as fh:
        fh.write(f"# started {dbmod.utcnow()} by {actor}: candidate {candidate} {label}\n")
        fh.flush()
        proc = popen(argv, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                     env=proxy_env(cfg), start_new_session=True, close_fds=True)
    st = {"pid": proc.pid, "candidate": candidate, "label": label, "actor": actor,
          "base_url": base_url, "started": dbmod.utcnow(), "started_ts": time.time()}
    (d / "state.json").write_text(json.dumps(st))
    return st


def request_stop(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise DecryptRunError("no decrypt is running")
    (folder(cfg, t) / "stop").write_text("stop")


def kill(cfg: Config, t: tmod.Target) -> None:
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise DecryptRunError("no decrypt is running")
    try:
        os.killpg(int(cur["pid"]), signal.SIGKILL)
    except ProcessLookupError:
        pass
    with open(folder(cfg, t) / "decrypt.log", "a") as fh:
        fh.write(f"# killed {dbmod.utcnow()}\n")


def result_text(cfg: Config, t: tmod.Target) -> str:
    """The decrypt log as one text item for padding-oracle-confirm."""
    st = status(cfg, t) or {}
    head = f"# wstg padding-oracle decrypt: candidate {st.get('candidate')} {st.get('label', '')}\n"
    body = st.get("log", "")
    text = head + body + "\n"
    room = evmod.MAX_TEXT_BYTES - 200
    return text if len(text.encode()) <= room else text[:room] + "\n... truncated\n"
