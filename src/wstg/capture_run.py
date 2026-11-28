"""Start and stop `wstg capture` from the web (Tools tab > Browser capture).

The web app starts `wstg capture TARGET --role R --url U --stop-file F` as a
background process on the tool's host; the Chromium window opens on that host's
desktop (display WSTG_CAPTURE_DISPLAY, default the app's DISPLAY or :0). The
tester walks the target there and presses *Stop and save* in the web page, which
writes "save" to the stop file (the command's replacement for pressing Enter);
*Discard* writes "discard" and nothing is stored. One capture per target at a time.

State lives in `<evidence root>/<target>/_capture/`: state.json (pid, role, URL,
start time, who), capture.log (the command's output), stop (the stop file).
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
from . import targets as tmod
from .config import Config

FOLDER = "_capture"
ROLES = [("user", "har-browse", "main walk, logged in as an ordinary user (do not log out)"),
         ("anon", "har-browse", "main walk without logging in"),
         ("admin", "har-browse", "main walk as an administrator (one capture per role)"),
         ("logout", "har-logout", "log in, open one page, log out (WSTG-SESS-06)"),
         ("timeout", "har-timeout", "log in, open one page, do not log out; collect session-timeout right after (WSTG-SESS-07)"),
         ("timeout-active", "har-timeout", "log in and keep clicking for the active-session timeout check")]
KILL_AFTER = 60          # seconds after a stop request before a kill is offered


class CaptureRunError(Exception):
    pass


def folder(cfg: Config, t: tmod.Target) -> Path:
    return tmod.evidence_dir(cfg, t) / FOLDER


def _alive(pid: int) -> bool:
    try:
        os.waitpid(pid, os.WNOHANG)          # reap it when it is our finished child
    except ChildProcessError:
        pass
    except OSError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:                                     # a zombie of another parent counts as finished
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][:1] != "Z"
    except (OSError, IndexError):
        return True


def status(cfg: Config, t: tmod.Target) -> dict | None:
    """The last capture of this target: its state plus running, stop request, log tail."""
    d = folder(cfg, t)
    try:
        st = json.loads((d / "state.json").read_text())
    except (OSError, ValueError):
        return None
    st["running"] = _alive(int(st.get("pid") or 0)) if st.get("pid") else False
    stop = d / "stop"
    st["stop_request"] = stop.read_text().strip() if stop.is_file() else ""
    st["stop_age"] = time.time() - stop.stat().st_mtime if stop.is_file() else 0
    st["can_kill"] = st["running"] and st["stop_request"] and st["stop_age"] > KILL_AFTER
    try:
        lines = (d / "capture.log").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    st["log"] = "\n".join(lines[-40:])
    st["elapsed"] = int(time.time() - st.get("started_ts", time.time()))
    return st


def proxy_env(cfg: Config) -> dict[str, str]:
    """The current environment with http_proxy/https_proxy set from WSTG_HTTP_PROXY (and
    no_proxy cleared), so a background tool that uses ep.fetch (wstg-forge, wstg-cryp) reaches
    the target through the proxy, like the collection runner does. Without this a proxied
    target is unreachable and every request times out."""
    env = dict(os.environ)
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY"):
        env.pop(k, None)
    if cfg.http_proxy:
        for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            env[k] = cfg.http_proxy
    env["PYTHONUNBUFFERED"] = "1"
    return env


def display_env(cfg: Config) -> dict[str, str]:
    env = dict(os.environ)
    env["DISPLAY"] = cfg.capture_display or os.environ.get("DISPLAY") or ":0"
    if not env.get("XAUTHORITY"):
        xa = Path.home() / ".Xauthority"
        if xa.is_file():
            env["XAUTHORITY"] = str(xa)
    env["PYTHONUNBUFFERED"] = "1"
    return env


def command(t: tmod.Target, role: str, url: str, stop_file: Path, actor: str = "web") -> list[str]:
    exe = Path(sys.executable).with_name("wstg")
    base = [str(exe)] if exe.is_file() else [sys.executable, "-m", "wstg.cli"]
    argv = base + ["capture", t.name, "--stop-file", str(stop_file), "--actor", actor]
    if role:
        argv += ["--role", role]
    if url:
        argv += ["--url", url]
    return argv


def start(cfg: Config, t: tmod.Target, *, role: str, url: str, actor: str, popen=subprocess.Popen) -> dict:
    """Start the capture process; refuses while one runs for this target."""
    cur = status(cfg, t)
    if cur and cur["running"]:
        raise CaptureRunError(f"a capture of {t.name} is already running (role {cur.get('role') or 'session'})")
    d = folder(cfg, t)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    stop = d / "stop"
    stop.unlink(missing_ok=True)
    log = d / "capture.log"
    env = display_env(cfg)
    with open(log, "w") as fh:
        fh.write(f"# started {dbmod.utcnow()} by {actor} on display {env['DISPLAY']}\n")
        fh.flush()
        proc = popen(command(t, role, url, stop, actor), stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                     env=env, start_new_session=True, close_fds=True)
    st = {"pid": proc.pid, "role": role, "url": url, "actor": actor, "started": dbmod.utcnow(),
          "started_ts": time.time(), "display": env["DISPLAY"]}
    (d / "state.json").write_text(json.dumps(st))
    return st


def request_stop(cfg: Config, t: tmod.Target, how: str) -> None:
    """how: "save" (store the capture) or "discard" (store nothing)."""
    if how not in ("save", "discard"):
        raise CaptureRunError("stop must be save or discard")
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise CaptureRunError("no capture is running")
    (folder(cfg, t) / "stop").write_text(how)


def kill(cfg: Config, t: tmod.Target) -> None:
    """Kill a capture that did not end after a stop request (its process group: the browser too)."""
    cur = status(cfg, t)
    if not cur or not cur["running"]:
        raise CaptureRunError("no capture is running")
    try:
        os.killpg(int(cur["pid"]), signal.SIGKILL)
    except ProcessLookupError:
        pass
    with open(folder(cfg, t) / "capture.log", "a") as fh:
        fh.write(f"# killed {dbmod.utcnow()}: nothing was stored\n")


def wait_for_stop_file(path: Path, poll: float = 1.0):
    """A `wait` for capture._drive: returns when the stop file appears."""
    def wait() -> None:
        print(f"  A browser window has opened. Walk the target, then press Stop and save in the web page "
              f"(or write 'save' to {path}).", flush=True)
        while not path.is_file():
            time.sleep(poll)
    return wait
