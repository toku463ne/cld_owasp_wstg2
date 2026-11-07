"""Web UI (Flask).

Security model:
- The app listens on loopback; nginx in front adds X-Forwarded-For. The client
  address is checked against WSTG_ALLOWED_NETWORKS on every request (nginx
  enforces the same list).
- Every page except the login page needs a logged-in user.
- Every POST, the login form included, must carry the session's CSRF token.
- Writes need the admin role, checked on the server. Hiding buttons from guests
  is only a convenience.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from . import catalog as catmod
from . import db as dbmod
from . import users
from .config import Config

CSRF_FIELD = "csrf"
CSRF_HEADER = "X-CSRF-Token"


def _local_path(value: str | None, default: str = "/") -> str:
    """A redirect target limited to paths on this site."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return default


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.user is None:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not users.can_write(g.user):
            abort(403)
        return fn(*a, **kw)
    return login_required(wrapper)


def create_app(cfg: Config, db: dbmod.Database | None = None, cat: catmod.Catalog | None = None) -> Flask:
    if not cfg.secret_key:
        raise RuntimeError("WSTG_SECRET_KEY (or WSTG_SECRET_KEY_FILE) is not set")
    db = db or dbmod.Database(cfg.db_path)
    pending = dbmod.pending_migrations(db)
    if pending:
        raise RuntimeError(f"database has pending migrations ({', '.join(v for v, _ in pending)}); run `wstg migrate`")

    cat = cat or catmod.load()

    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config.update(
        SECRET_KEY=cfg.secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Served over plain HTTP on the LAN for now (port 8083). Set to True
        # when the tool moves behind TLS.
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_NAME="wstg_session",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=50 * 1024 * 1024,
    )
    app.extensions["wstg.cfg"] = cfg
    app.extensions["wstg.db"] = db
    app.extensions["wstg.catalog"] = cat

    static_versions: dict[str, str] = {}

    def static_url(filename: str) -> str:
        """Static file URL with a content hash, so browsers never keep an old file."""
        if filename not in static_versions:
            data = (Path(app.static_folder) / filename).read_bytes()
            static_versions[filename] = hashlib.sha256(data).hexdigest()[:12]
        return url_for("static", filename=filename, v=static_versions[filename])

    app.jinja_env.globals["static_url"] = static_url

    @app.before_request
    def guard():
        if not cfg.client_allowed(request.remote_addr):
            abort(403)
        g.user = users.get(db, session["uid"]) if "uid" in session else None
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            sent = request.form.get(CSRF_FIELD) or request.headers.get(CSRF_HEADER) or ""
            if not secrets.compare_digest(sent, session["csrf"]):
                abort(400, "missing or invalid CSRF token")

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        return resp

    @app.context_processor
    def inject():
        return {"user": g.get("user"), "csrf": session.get("csrf", ""),
                "can_write": users.can_write(g.get("user"))}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            name = request.form.get("username", "")[:64]
            u = users.authenticate(db, name, request.form.get("password", ""))
            with db.tx() as conn:
                db.audit(conn, name or "-", "login.ok" if u else "login.fail", remote=request.remote_addr)
            if u:
                session.clear()
                session.permanent = True
                session["uid"] = u["id"]
                session["csrf"] = secrets.token_urlsafe(32)
                return redirect(_local_path(request.args.get("next")))
            flash("Invalid user name or password.")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/admin/users")
    @admin_required
    def admin_users():
        return render_template("admin_users.html", users=users.list_all(db), roles=users.ROLES)

    @app.post("/admin/users")
    @admin_required
    def admin_users_add():
        try:
            users.add(db, request.form.get("username", "").strip(), request.form.get("password", ""),
                      request.form.get("role", ""), actor=g.user["username"])
            flash("User added.")
        except users.UserError as e:
            flash(str(e))
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<username>/disabled")
    @admin_required
    def admin_users_disabled(username: str):
        try:
            users.set_disabled(db, username, request.form.get("disabled") == "1", actor=g.user["username"])
        except users.UserError as e:
            flash(str(e))
        return redirect(url_for("admin_users"))

    from . import evidence as evmod
    from . import web_evidence, web_findings, web_targets
    store = evmod.Store(cfg, db)
    app.extensions["wstg.store"] = store
    web_targets.register(app, cfg, db, cat, store)
    web_evidence.register(app, store, cat)
    web_findings.register(app, db, cat)

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    def error_page(e):
        return render_template("error.html", error=e), e.code

    return app
