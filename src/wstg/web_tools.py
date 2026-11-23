"""Tools tab: helpers the tester uses by hand while testing.

URLs: /t/<target>/tools (list), /t/<target>/tools/replay (request replay).

Request replay reads a request copied from Burp (raw text or a 'Save items' XML
export), applies the changes asked for, and shows an equivalent curl command,
a `wstg-replay` command line, and a standalone Python script. An admin may also
send it once from here: the host and port must be in the target's scope record,
and a method that may change the target (anything but GET, HEAD, OPTIONS,
TRACE) needs the owner's agreement ticked. Each send is written to the audit
log (method, URL, status; not the headers or body).
"""
from __future__ import annotations

import http.client
import shlex

from flask import Flask, abort, g, render_template, request, session

from . import db as dbmod
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
                "(scope-checked)."},
]


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]


def register(app: Flask, cfg: Config, db: dbmod.Database) -> None:

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
        ctx = {"tab": "tools", "form": f, "req": None, "error": "", "resp": None, "send_error": "",
               "scope_error": "", "proxy": cfg.http_proxy}
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
                     status=status)
        return render_template("tool_replay.html", **ctx)


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
