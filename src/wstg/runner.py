"""Automatic evidence collection: plan, queue, run (worker), resume.

- A job collects the automatic evidence of one target, in catalog order.
  `light` mode skips `level: full` evidence (slow, heavy, noisy tools).
- Evidence that already has a complete version is skipped, so running the
  same mode again after an interruption continues where it stopped.
- Every command is rendered, then checked against the target's scope record
  (`targets.check_command`) right before it runs. Refused commands do not run.
- A command runs without a shell and without stdin, in a temp folder inside
  the evidence folder ({out}); stdout/stderr go to files there. Only an exit
  code in `ok_exit_codes` with every declared output file present makes a
  complete version; anything else is recorded as a failed version, which never
  becomes `latest` and is never a pass.
- One worker process (`wstg worker`) runs jobs one at a time. On start it marks
  jobs left running by a dead worker as interrupted.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass

from . import catalog as catmod
from . import db as dbmod
from . import evidence as evmod
from . import targets as tmod
from .config import Config

MODES = ("light", "full")
ACTIVE = ("queued", "running", "cancelling")
POLL_SECONDS = 1.0
MAX_STDOUT_BYTES = 200 * 1024 * 1024


class RunError(Exception):
    pass


@dataclass
class Outcome:
    status: str             # complete | failed | refused | skipped | cancelled
    message: str = ""
    version: int | None = None
    exit_code: int | None = None


def plan(cat: catmod.Catalog, target: tmod.Target, mode: str) -> list[catmod.Evidence]:
    if mode not in MODES:
        raise RunError(f"mode must be one of {', '.join(MODES)}")
    evs = [e for e in cat.evidence.values() if e.kind == "auto" and e.target_type == target.type]
    if mode == "light":
        evs = [e for e in evs if e.level == "light"]
    # Light (quick) evidence first, heavy last, catalog order otherwise.
    return sorted(evs, key=lambda e: (e.level == "full", e.heavy))


def active_job(db: dbmod.Database, target: tmod.Target) -> dict | None:
    return db.one(f"SELECT * FROM jobs WHERE target_id = ? AND status IN ({','.join('?' * len(ACTIVE))})"
                  " ORDER BY id DESC", (target.id, *ACTIVE))


def last_job(db: dbmod.Database, target: tmod.Target) -> dict | None:
    return db.one("SELECT * FROM jobs WHERE target_id = ? ORDER BY id DESC", (target.id,))


def job_items(db: dbmod.Database, job_id: int) -> list[dict]:
    return db.query("SELECT * FROM job_items WHERE job_id = ? ORDER BY seq", (job_id,))


def enqueue(db: dbmod.Database, cat: catmod.Catalog, target: tmod.Target, mode: str, actor: str) -> int:
    problems = tmod.scope_problems(tmod.get_scope(db, target))
    if problems:
        raise RunError(f"set the scope record of {target.name} first: {'; '.join(problems)}")
    evs = plan(cat, target, mode)
    if not evs:
        raise RunError(f"no automatic evidence for {target.type} targets in {mode} mode")
    with db.tx() as conn:
        busy = conn.execute(
            f"SELECT id FROM jobs WHERE target_id = ? AND status IN ({','.join('?' * len(ACTIVE))})",
            (target.id, *ACTIVE)).fetchone()
        if busy:
            raise RunError(f"job {busy[0]} for {target.name} is still active")
        cur = conn.execute("INSERT INTO jobs (target_id, mode, status, created_at, created_by) VALUES (?,?,?,?,?)",
                           (target.id, mode, "queued", dbmod.utcnow(), actor))
        job_id = cur.lastrowid
        conn.executemany("INSERT INTO job_items (job_id, seq, evidence_id, status) VALUES (?,?,?,'pending')",
                         [(job_id, i, e.id) for i, e in enumerate(evs, 1)])
        db.audit(conn, actor, "job.enqueue", target=target.name, job=job_id, mode=mode, items=len(evs))
    return job_id


def cancel(db: dbmod.Database, job_id: int, actor: str) -> None:
    with db.tx() as conn:
        conn.execute("UPDATE jobs SET status = 'cancelled', finished_at = ? WHERE id = ? AND status = 'queued'",
                     (dbmod.utcnow(), job_id))
        conn.execute("UPDATE jobs SET status = 'cancelling' WHERE id = ? AND status = 'running'", (job_id,))
        conn.execute("UPDATE job_items SET status = 'cancelled' WHERE job_id = ? AND status = 'pending'"
                     " AND (SELECT status FROM jobs WHERE id = ?) = 'cancelled'", (job_id, job_id))
        db.audit(conn, actor, "job.cancel", job=job_id)


# --------------------------------------------------------------------------
# Running


class Runner:
    def __init__(self, cfg: Config, db: dbmod.Database, cat: catmod.Catalog, store: evmod.Store):
        self.cfg, self.db, self.cat, self.store = cfg, db, cat, store
        self.worker = f"{socket.gethostname()}:{os.getpid()}"

    def env(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items()
               if k in ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "USER", "TMPDIR")}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        env.setdefault("LANG", "C.UTF-8")
        for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY"):
            env.pop(k, None)
        if self.cfg.http_proxy:
            for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
                env[k] = self.cfg.http_proxy
        return env

    def _heartbeat(self, job_id: int) -> str:
        """Update the heartbeat; return the job status (to notice cancelling)."""
        with self.db.tx() as conn:
            conn.execute("UPDATE jobs SET heartbeat_at = ? WHERE id = ?", (dbmod.utcnow(), job_id))
            return conn.execute("SELECT status FROM jobs WHERE id = ?", (job_id,)).fetchone()[0]

    def collect(self, target: tmod.Target, ev: catmod.Evidence, *, job_id: int | None = None,
                actor: str = "worker") -> Outcome:
        """Run one evidence command and store the result (complete or failed)."""
        scope = tmod.get_scope(self.db, target)
        values = tmod.placeholder_values(self.cfg, target, scope)
        tmp = self.store.begin(target, ev.id)
        values["out"] = str(tmp)
        argv = [catmod.render(a, values) for a in ev.argv]
        leftover = [a for a in argv if catmod.PLACEHOLDER_RE.search(a)]
        try:
            if leftover:
                raise tmod.ScopeError(f"unfilled placeholder in {leftover[0]!r}")
            tmod.check_command(target, scope, argv, passive=ev.passive)
        except tmod.ScopeError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            return Outcome("refused", str(e))
        tool = shutil.which(argv[0], path=self.env()["PATH"])
        if not tool:
            shutil.rmtree(tmp, ignore_errors=True)
            return Outcome("failed", f"tool not installed: {argv[0]}")

        started = dbmod.utcnow()
        t0 = time.monotonic()
        exit_code, message, cancelled = None, "", False
        with open(tmp / "stdout.txt", "wb") as out, open(tmp / "stderr.txt", "wb") as err:
            try:
                proc = subprocess.Popen([tool, *argv[1:]], cwd=tmp, stdin=subprocess.DEVNULL, stdout=out,
                                        stderr=err, env=self.env(), start_new_session=True)
            except OSError as e:
                shutil.rmtree(tmp, ignore_errors=True)
                return Outcome("failed", f"cannot start {argv[0]}: {e}")
            next_beat = 0.0
            while True:
                try:
                    exit_code = proc.wait(timeout=POLL_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    pass
                elapsed = time.monotonic() - t0
                if job_id and elapsed >= next_beat:
                    next_beat = elapsed + 5
                    if self._heartbeat(job_id) == "cancelling":
                        cancelled, message = True, "cancelled while running"
                if elapsed > ev.timeout:
                    message = f"timed out after {ev.timeout} s"
                if cancelled or message or (tmp / "stdout.txt").stat().st_size > MAX_STDOUT_BYTES:
                    message = message or "stdout larger than 200 MB"
                    _kill(proc)
                    exit_code = proc.wait()
                    break
        duration = round(time.monotonic() - t0, 1)

        items = [evmod.Item("text", "stdout.txt", "", 0, caption="stdout", mime="text/plain")]
        if (tmp / "stderr.txt").stat().st_size:
            items.append(evmod.Item("text", "stderr.txt", "", 0, caption="stderr", mime="text/plain"))
        else:
            (tmp / "stderr.txt").unlink()
        missing = []
        for rel in ev.files:
            p = tmp / rel
            if p.is_dir():
                for f in sorted(x for x in p.rglob("*") if x.is_file() and not x.is_symlink()):
                    items.append(evmod.Item("file", str(f.relative_to(tmp)), "", 0, name=f.name))
            elif p.is_file() and not p.is_symlink():
                items.append(evmod.Item("file", rel, "", 0, name=p.name))
            else:
                missing.append(rel)
        if not message:
            if exit_code not in ev.ok_exit_codes:
                message = f"exit code {exit_code}"
            elif missing:
                message = f"missing output: {', '.join(missing)}"
        status = "failed" if message else "complete"
        cmd_line = " ".join(argv)
        (tmp / "command.txt").write_text(cmd_line + "\n")
        v = self.store.commit(
            target, ev.id, tmp, source="auto", actor=actor, status=status,
            summary=("collected" if status == "complete" else f"failed: {message}"), items=items,
            extra_meta={"argv": argv, "exit_code": exit_code, "started_at": started, "duration_s": duration,
                        "tool": tool, "job_id": job_id, "proxy": bool(self.cfg.http_proxy),
                        "message": message, "files": {"command.txt": {}}})
        if cancelled:
            return Outcome("cancelled", message, v.version, exit_code)
        return Outcome(status, message, v.version, exit_code)

    def run_job(self, job_id: int) -> str:
        job = self.db.one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        target = tmod.get(self.db, self.db.one("SELECT name FROM targets WHERE id = ?", (job["target_id"],))["name"])
        final = "done"
        for item in job_items(self.db, job_id):
            if item["status"] != "pending":
                continue
            if self._heartbeat(job_id) == "cancelling":
                final = "cancelled"
                break
            ev = self.cat.evidence.get(item["evidence_id"])
            if ev is None:
                out = Outcome("failed", "no longer in the catalog")
            else:
                latest = self.store.load(target.name, ev.id)
                if latest:
                    out = Outcome("skipped", f"already collected (v{latest.version})", latest.version)
                else:
                    self._set_item(job_id, item["seq"], "running", started=True)
                    try:
                        out = self.collect(target, ev, job_id=job_id)
                    except Exception as e:  # never leave an item running
                        out = Outcome("failed", f"error: {e}")
            self._set_item(job_id, item["seq"], out.status, message=out.message, version=out.version,
                           exit_code=out.exit_code, finished=True)
            if out.status == "cancelled":
                final = "cancelled"
                break
        with self.db.tx() as conn:
            if final == "cancelled":
                conn.execute("UPDATE job_items SET status = 'cancelled' WHERE job_id = ? AND status = 'pending'",
                             (job_id,))
            conn.execute("UPDATE jobs SET status = ?, finished_at = ? WHERE id = ?",
                         (final, dbmod.utcnow(), job_id))
            self.db.audit(conn, "worker", "job.finish", job=job_id, status=final)
        return final

    def _set_item(self, job_id, seq, status, *, message="", version=None, exit_code=None,
                  started=False, finished=False):
        now = dbmod.utcnow()
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE job_items SET status = ?, message = ?, version = COALESCE(?, version),"
                " exit_code = COALESCE(?, exit_code),"
                " started_at = CASE WHEN ? THEN ? ELSE started_at END,"
                " finished_at = CASE WHEN ? THEN ? ELSE finished_at END WHERE job_id = ? AND seq = ?",
                (status, message, version, exit_code, started, now, finished, now, job_id, seq))

    # ---- worker ---------------------------------------------------------

    def recover(self) -> list[int]:
        """Mark jobs left running by a worker that is gone as interrupted.
        A later job in the same mode skips what was already collected."""
        ids = [r["id"] for r in self.db.query("SELECT id FROM jobs WHERE status IN ('running', 'cancelling')")]
        if ids:
            with self.db.tx() as conn:
                for i in ids:
                    conn.execute("UPDATE job_items SET status = 'failed', message = 'interrupted'"
                                 " WHERE job_id = ? AND status = 'running'", (i,))
                    conn.execute("UPDATE jobs SET status = 'interrupted', finished_at = ? WHERE id = ?",
                                 (dbmod.utcnow(), i))
                    self.db.audit(conn, "worker", "job.interrupted", job=i)
        # Temp folders of interrupted collections are never evidence.
        for tmp in self.cfg.evidence_root.glob("*/*/.tmp-*"):
            shutil.rmtree(tmp, ignore_errors=True)
        return ids

    def claim(self) -> int | None:
        with self.db.tx() as conn:
            row = conn.execute("SELECT id FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
            if not row:
                return None
            now = dbmod.utcnow()
            conn.execute("UPDATE jobs SET status = 'running', started_at = ?, heartbeat_at = ?, worker = ?"
                         " WHERE id = ?", (now, now, self.worker, row[0]))
            return row[0]

    def serve(self, once: bool = False, poll: float = 2.0) -> None:
        self.recover()
        while True:
            job_id = self.claim()
            if job_id is not None:
                self.run_job(job_id)
                continue
            if once:
                return
            time.sleep(poll)


def _kill(proc: subprocess.Popen) -> None:
    """Stop the command and everything it started (own process group)."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def stale(db: dbmod.Database, cfg: Config, job: dict) -> bool:
    """True when a running job's worker stopped sending heartbeats."""
    if job["status"] not in ("running", "cancelling") or not job["heartbeat_at"]:
        return False
    from datetime import datetime, timezone
    hb = datetime.fromisoformat(job["heartbeat_at"].replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - hb).total_seconds() > cfg.job_stale_seconds

