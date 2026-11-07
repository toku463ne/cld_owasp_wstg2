"""Findings: list (tab), create from a WSTG page, detail and edit, CVSS API."""

from __future__ import annotations

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, url_for

from . import catalog as catmod
from . import cvss
from . import db as dbmod
from . import findings as fmod
from . import targets as tmod
from . import users
from .web import admin_required, login_required


def register(app: Flask, db: dbmod.Database, cat: catmod.Catalog) -> None:

    def load_target(name: str) -> tmod.Target:
        t = tmod.get(db, name)
        if not t:
            abort(404)
        g.target = t
        return t

    def form_data() -> dict:
        return {k: request.form.get(k, "") for k in (*fmod.TEXT_FIELDS, "status", "cvss_vector", "kind", "subject")}

    def kinds_for(test_id: str) -> list:
        """The test's kinds first, then the others (a finding may use any kind)."""
        sc = cat.scenarios.get(test_id)
        own = [cat.finding_kinds[k] for k in (sc.finding_kinds if sc else ()) if k in cat.finding_kinds]
        return own + [k for k in cat.finding_kinds.values() if k not in own]

    def fail(e: fmod.FindingError, t) -> None:
        if e.existing is not None:
            flash(f"Not saved: finding {e.existing} already covers this kind and subject. Open it with the link below "
                  "and add to it instead.")
            g.duplicate = url_for("finding_page", name=t.name, fid=e.existing)
        else:
            flash(str(e))

    @app.get("/t/<name>/findings")
    @login_required
    def findings_tab(name: str):
        t = load_target(name)
        return render_template("findings_tab.html", tab="findings", findings=fmod.list_for(db, t), cat=cat)

    @app.route("/t/<name>/findings/new", methods=["GET", "POST"])
    @admin_required
    def finding_new(name: str):
        t = load_target(name)
        test_id = request.values.get("test", "")
        test = cat.tests.get(test_id)
        if not test:
            abort(400, "a finding is created from a WSTG page (test=WSTG-...)")
        data = {"status": "open", "title": "", "cvss_vector": ""}
        if request.method == "POST":
            data = form_data()
            try:
                fid = fmod.create(db, t, test_id, data, g.user["username"], kinds=cat.finding_kinds)
                flash("Finding created.")
                return redirect(url_for("finding_page", name=t.name, fid=fid))
            except fmod.FindingError as e:
                fail(e, t)
        return render_template("finding.html", tab="findings", finding=None, data=data, test=test,
                               kinds=kinds_for(test_id),
                               metrics=cvss.METRICS, statuses=fmod.STATUSES,
                               score=cvss.try_score(data.get("cvss_vector")))

    @app.route("/t/<name>/findings/<int:fid>", methods=["GET", "POST"])
    @login_required
    def finding_page(name: str, fid: int):
        t = load_target(name)
        f = fmod.get(db, t, fid)
        if not f:
            abort(404)
        data = f
        if request.method == "POST":
            if not users.can_write(g.user):
                abort(403)
            data = form_data()
            try:
                fmod.update(db, t, fid, data, g.user["username"], kinds=cat.finding_kinds)
                flash("Saved.")
                return redirect(url_for("finding_page", name=t.name, fid=fid))
            except fmod.FindingError as e:
                fail(e, t)
        return render_template("finding.html", tab="findings", finding=f, data=data, kinds=kinds_for(f["test_id"]),
                               test=cat.tests.get(f["test_id"]), metrics=cvss.METRICS,
                               statuses=fmod.STATUSES, score=cvss.try_score(data.get("cvss_vector")))

    @app.get("/api/cvss")
    @login_required
    def api_cvss():
        try:
            return jsonify(cvss.score(request.args.get("vector", "")))
        except cvss.CvssError as e:
            return jsonify(error=str(e)), 400
