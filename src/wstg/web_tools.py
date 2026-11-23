"""Tools tab: helpers the tester uses by hand while testing.

URLs: /t/<target>/tools (list), /t/<target>/tools/replay (request replay).

Request replay reads a request copied from Burp (raw text or a 'Save items' XML
export), applies the changes asked for, and shows an equivalent curl command,
a `wstg-replay` command line, and a standalone Python script. An admin may also
send it once from here: the host and port must be in the target's scope record,
and a method that may change the target (anything but GET, HEAD, OPTIONS,
TRACE) needs the owner's agreement ticked. Each send is written to the audit
log (method, URL, status; not the headers or body).

Opened from a manual evidence page (`?ev=<evidence id>`), the page keeps that
evidence and *Send once* also adds the request as sent and the response (or the
error) to it as a new text item, so the replay is kept with the test.
"""
from __future__ import annotations

import http.client
import shlex

from flask import Flask, abort, g, render_template, request, session

from . import catalog as catmod
from . import db as dbmod
from . import evidence as evmod
from . import replay as rp
from . import targets as tmod
from . import users
from .config import Config
from .web import login_required

MAX_RAW = 2 * 1024 * 1024
SHOW_BODY = 64 * 1024

TOOLS = [
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

    @app.route("/t/<name>/tools/replay", methods=["GET", "POST"])
    @login_required
    def tool_replay(name: str):
        t = load_target(name)
        f = request.form
        ev = target_evidence(t, (f.get("ev") or request.args.get("ev", "")).strip())
        ctx = {"tab": "tools", "form": f, "req": None, "error": "", "resp": None, "send_error": "",
               "scope_error": "", "proxy": cfg.http_proxy, "ev": ev, "saved": None}
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
                     status=status, evidence=ev.id if ev and f.get("save") == "1" else None)
        if ev and f.get("save") == "1":
            result = f"{status} {ctx['resp'].reason}" if status else "no answer"
            caption = f.get("caption", "").strip() or f"Replay: {req.method} {req.url} -> {result}"
            try:
                v = store.add_text(t, ev.id, evidence_text(req, ctx["resp"], ctx["send_error"], g.user["username"],
                                                           cfg.http_proxy), caption, g.user["username"])
                ctx["saved"] = v.version
            except evmod.EvidenceError as e:
                ctx["send_error"] = (ctx["send_error"] + "; " if ctx["send_error"] else "") + f"not added: {e}"
        return render_template("tool_replay.html", **ctx)


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
