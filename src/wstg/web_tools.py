"""Tools tab: helpers the tester uses by hand while testing.

URLs: /t/<target>/tools (list), /t/<target>/tools/replay (request replay),
/t/<target>/tools/capture (browser capture: start `wstg capture` from the web; see
capture_run.py).

Request replay reads a request copied from Burp (raw text or a 'Save items' XML
export), applies the changes asked for, and shows an equivalent curl command,
a `wstg-replay` command line, and a standalone Python script. An admin may also
send it once from here: the host and port must be in the target's scope record,
and a method that may change the target (anything but GET, HEAD, OPTIONS,
TRACE) needs the owner's agreement ticked. Each send is written to the audit
log (method, URL, status; not the headers or body).

Opened from a manual evidence page (`?ev=<evidence id>`), the page keeps that
evidence. After *Send once* the result is shown first; *Add to <evidence>* then
adds the request as sent and the response (or the error) to it as a new text
item, without sending again. Until then the result waits in
`<evidence root>/<target>/_replay/<random>.json` (owner-only; removed when added,
or after a day).
"""
from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import shlex
import time
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

from . import capture as capmod
from . import capture_run as crun
from . import catalog as catmod
from . import db as dbmod
from . import evidence as evmod
from . import replay as rp
from . import targets as tmod
from . import users
from .config import Config
from .web import admin_required, login_required

MAX_RAW = 2 * 1024 * 1024
SHOW_BODY = 64 * 1024
PENDING = "_replay"
PENDING_TTL = 86400
_TOKEN_RE = re.compile(r"[0-9a-f]{32}")

TOOLS = [
    {"endpoint": "tool_capture", "title": "Browser capture",
     "summary": "Record a browsing session (HAR, storage state, and the pages after JavaScript) into har-browse, "
                "har-logout, or har-timeout: start it here, walk the target in the Chromium window that opens on "
                "the tool's host desktop, then press Stop and save here. Replaces running `wstg capture` "
                "in a terminal."},
    {"endpoint": "tool_replay", "title": "Request replay",
     "summary": "Paste a request from Burp (Proxy history or Repeater: Copy to file, or select all and copy), "
                "change headers, cookies, or parameters, and get a curl command, a wstg-replay command line, "
                "or a Python script for repeated requests. An admin can send it once from here "
                "(scope-checked). Opened from a manual evidence page, it adds the request and response "
                "to that evidence."},
]


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]


def register(app: Flask, cfg: Config, db: dbmod.Database, cat: catmod.Catalog, store: evmod.Store) -> None:

    def target_evidence(t: tmod.Target, eid: str) -> catmod.Evidence | None:
        """The manual evidence of this target a replay may be added to (404 when not)."""
        if not eid:
            return None
        ev = cat.evidence.get(eid)
        if not ev or ev.kind != "manual" or tmod.evidence_owner(t, ev.target_type) != t.name:
            abort(404)
        return ev

    def load_target(name: str) -> tmod.Target:
        t = tmod.get(db, name)
        if not t:
            abort(404)
        g.target = t
        session["target"] = t.name
        return t

    @app.get("/t/<name>/tools")
    @login_required
    def tools_tab(name: str):
        load_target(name)
        return render_template("tools_tab.html", tab="tools", tools=TOOLS)

    @app.get("/t/<name>/tools/capture")
    @login_required
    def tool_capture(name: str):
        t = load_target(name)
        st = crun.status(cfg, t)
        problem, base_url = "", ""
        if t.type != "fqdn":
            problem = "a browser capture needs an FQDN target"
        else:
            try:
                scope = tmod.get_scope(db, t)
                base_url = scope.base_url or f"https://{t.name}"
                probs = tmod.scope_problems(scope)
                if probs:
                    problem = "the scope record does not allow it yet: " + "; ".join(probs)
            except tmod.TargetError as e:
                problem = str(e)
        role = request.args.get("role", "user")
        return render_template("tool_capture.html", tab="tools", st=st, problem=problem, base_url=base_url,
                               roles=crun.ROLES, role=role, display=crun.display_env(cfg)["DISPLAY"],
                               kill_after=crun.KILL_AFTER)

    @app.post("/t/<name>/tools/capture/start")
    @admin_required
    def tool_capture_start(name: str):
        t = load_target(name)
        role = request.form.get("role", "").strip()
        url = request.form.get("url", "").strip()
        try:
            if role and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}", role):
                raise crun.CaptureRunError("a role is letters, digits, '-' and '_' (for example user, admin, logout)")
            if t.type != "fqdn":
                raise crun.CaptureRunError("a browser capture needs an FQDN target")
            scope = tmod.get_scope(db, t)
            probs = tmod.scope_problems(scope)
            if probs:
                raise crun.CaptureRunError("the scope record does not allow it: " + "; ".join(probs))
            capmod._start_url(t, scope, url or None)
            crun.start(cfg, t, role=role, url=url, actor=g.user["username"])
            with db.tx() as conn:
                db.audit(conn, g.user["username"], "tool.capture.start", target=t.name, role=role, url=url or None)
            flash("Capture started: the browser opens on the tool's host. Walk the target, then press Stop and save.")
        except (crun.CaptureRunError, capmod.CaptureError, tmod.TargetError, tmod.ScopeError, OSError) as e:
            flash(f"Not started: {e}")
        return redirect(url_for("tool_capture", name=t.name))

    @app.post("/t/<name>/tools/capture/stop")
    @admin_required
    def tool_capture_stop(name: str):
        t = load_target(name)
        try:
            if request.form.get("how") == "kill":
                crun.kill(cfg, t)
            else:
                crun.request_stop(cfg, t, request.form.get("how", "save"))
        except (crun.CaptureRunError, OSError) as e:
            flash(str(e))
        return redirect(url_for("tool_capture", name=t.name))

    @app.route("/t/<name>/tools/replay", methods=["GET", "POST"])
    @login_required
    def tool_replay(name: str):
        t = load_target(name)
        f = request.form
        ev = target_evidence(t, (f.get("ev") or request.args.get("ev", "")).strip())
        ctx = {"tab": "tools", "form": f, "req": None, "error": "", "resp": None, "send_error": "",
               "scope_error": "", "proxy": cfg.http_proxy, "ev": ev, "saved": None, "pending": "",
               "caption": ""}
        if request.method == "GET":
            return render_template("tool_replay.html", **ctx)
        raw = f.get("raw", "")
        if len(raw) > MAX_RAW:
            ctx["error"] = f"the request is longer than {MAX_RAW // 1024} KB"
            return render_template("tool_replay.html", **ctx), 400
        try:
            base = rp.load(raw.encode("utf-8"), f.get("scheme") or None, int(f.get("item") or 1))
            req = rp.apply(base, method=f.get("method", "").strip(), path=f.get("path", "").strip(),
                           headers=_lines(f.get("headers", "")), cookies=_lines(f.get("cookies", "")),
                           no_cookies=f.get("no_cookies") == "1", params=_lines(f.get("params", "")),
                           body=f.get("body").replace("\r\n", "\n").encode("utf-8") if f.get("replace_body") == "1" else None)
        except (rp.ReplayError, ValueError) as e:
            ctx["error"] = str(e)
            return render_template("tool_replay.html", **ctx), 400
        ctx["req"] = req
        ctx["raw_out"] = req.raw().decode("utf-8", "replace")
        ctx["curl"] = rp.to_curl(req, cfg.http_proxy)
        ctx["python"] = rp.to_python(req)
        ctx["cli"] = _cli(f)
        try:
            tmod.check_command(t, tmod.get_scope(db, t), [f"{req.scheme}://{_hostport(req)}/"], passive=False)
        except (tmod.ScopeError, tmod.TargetError) as e:
            ctx["scope_error"] = str(e)
        if f.get("action") == "save":
            if not users.can_write(g.user):
                abort(403)
            if not ev:
                abort(400, "no evidence to add to")
            try:
                item, path = read_pending(cfg, t, f.get("pending", ""), ev.id)
                v = store.add_text(t, ev.id, item["text"], f.get("caption", "").strip() or item["caption"],
                                   g.user["username"])
                path.unlink(missing_ok=True)
                ctx["saved"] = v.version
            except (evmod.EvidenceError, ValueError) as e:
                ctx["send_error"] = f"not added: {e}"
                return render_template("tool_replay.html", **ctx), 400
            return render_template("tool_replay.html", **ctx)
        if f.get("action") != "send":
            return render_template("tool_replay.html", **ctx)
        if not users.can_write(g.user):
            abort(403)
        if ctx["scope_error"]:
            ctx["send_error"] = "not sent: " + ctx["scope_error"]
            return render_template("tool_replay.html", **ctx), 403
        if not req.safe and f.get("agree") != "1":
            ctx["send_error"] = (f"not sent: {req.method} may change the target; tick the box to confirm "
                                 "the owner agreed to such requests")
            return render_template("tool_replay.html", **ctx), 400
        try:
            resp = rp.send(req, proxy=cfg.http_proxy)
            ctx["resp"] = resp
            ctx["resp_body"] = rp.body_preview(resp.body, SHOW_BODY)
            status = resp.status
        except (OSError, http.client.HTTPException) as e:
            ctx["send_error"] = f"no answer: {e.__class__.__name__}: {e}"
            status = None
        with db.tx() as conn:
            db.audit(conn, g.user["username"], "tool.replay", target=t.name, method=req.method, url=req.url,
                     status=status)
        if ev:
            result = f"{status} {ctx['resp'].reason}" if status else "no answer"
            ctx["caption"] = f"Replay: {req.method} {req.url} -> {result}"
            text = evidence_text(req, ctx["resp"], ctx["send_error"], g.user["username"], cfg.http_proxy)
            ctx["pending"] = put_pending(cfg, t, ev.id, text, ctx["caption"])
        return render_template("tool_replay.html", **ctx)


def _pending_dir(cfg: Config, t: tmod.Target) -> Path:
    return tmod.evidence_dir(cfg, t) / PENDING


def put_pending(cfg: Config, t: tmod.Target, eid: str, text: str, caption: str) -> str:
    """Keep a replay result until the tester adds it (or not); returns its token.
    Results older than a day are removed on the way."""
    d = _pending_dir(cfg, t)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = time.time()
    for old in d.glob("*.json"):
        try:
            if now - old.stat().st_mtime > PENDING_TTL:
                old.unlink()
        except OSError:
            pass
    token = secrets.token_hex(16)
    fd = os.open(d / f"{token}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"ev": eid, "text": text, "caption": caption}, fh)
    return token


def read_pending(cfg: Config, t: tmod.Target, token: str, eid: str) -> tuple[dict, Path]:
    """The kept result for this evidence and its file (ValueError when gone)."""
    if not _TOKEN_RE.fullmatch(token or ""):
        raise ValueError("no replay result to add; send the request first")
    p = _pending_dir(cfg, t) / f"{token}.json"
    try:
        item = json.loads(p.read_text())
    except (OSError, ValueError):
        raise ValueError("the replay result is gone (already added, or older than a day); send it again") from None
    if item.get("ev") != eid:
        raise ValueError("the replay result was made for another evidence")
    return item, p


def evidence_text(req: rp.Request, resp: rp.Response | None, error: str, actor: str, proxy: str) -> str:
    """The request as sent and the response, as one text item (cut to fit the 1 MB text limit)."""
    head = (f"# wstg replay: {req.method} {req.url}\n# sent {dbmod.utcnow()} by {actor}"
            + (f" via {proxy}" if proxy else "") + "\n\n## Request\n\n")
    text = head + req.raw().decode("utf-8", "replace") + "\n\n## Response\n\n"
    if resp is None:
        return text + (error or "no answer") + "\n"
    text += f"# {resp.summary()}\n" + resp.raw_head() + "\n"
    room = evmod.MAX_TEXT_BYTES - len(text.encode()) - 200
    body = resp.body
    if len(body) > room:
        return text + body[:max(room, 0)].decode("utf-8", "replace") + f"\n... {len(body) - max(room, 0)} more bytes not kept\n"
    return text + body.decode("utf-8", "replace") + "\n"


def _hostport(req: rp.Request) -> str:
    host = f"[{req.host}]" if ":" in req.host else req.host
    return f"{host}:{req.port}"


def _cli(f) -> str:
    """The wstg-replay command line for the changes in the form (the request saved as request.txt)."""
    parts = ["wstg-replay", "request.txt"]
    if f.get("scheme"):
        parts += ["--scheme", f.get("scheme")]
    if (f.get("item") or "1") != "1":
        parts += ["--item", f.get("item")]
    if f.get("method", "").strip():
        parts += ["-X", f.get("method").strip()]
    if f.get("path", "").strip():
        parts += ["--path", f.get("path").strip()]
    for h in _lines(f.get("headers", "")):
        parts += ["-H", h]
    if f.get("no_cookies") == "1":
        parts.append("--no-cookies")
    for c in _lines(f.get("cookies", "")):
        parts += ["--cookie", c]
    if f.get("replace_body") == "1":
        parts += ["--body", f.get("body", "").replace("\r\n", "\n")]
    for p in _lines(f.get("params", "")):
        parts += ["-p", p]
    return " ".join(shlex.quote(p) for p in parts)
