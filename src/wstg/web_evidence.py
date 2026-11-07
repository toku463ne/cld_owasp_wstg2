"""Evidence pages: view a version, add images / files / text, edit, remove, download.

Evidence of the parent domain is shown on the domain target's pages; an FQDN
page that links to it is redirected there. Every write needs the admin role.
"""

from __future__ import annotations

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request, send_file,
                   url_for)

from . import catalog as catmod
from . import evidence as evmod
from . import targets as tmod
from .web import admin_required, login_required


def register(app: Flask, store: evmod.Store, cat: catmod.Catalog) -> None:

    def resolve(name: str, eid: str) -> tuple[tmod.Target, catmod.Evidence]:
        t = tmod.get(store.db, name)
        ev = cat.evidence.get(eid)
        if not t or not ev:
            abort(404)
        owner = tmod.evidence_owner(t, ev.target_type)
        if owner is None:
            abort(404)
        if owner != t.name:
            if request.method != "GET":
                abort(400, "write to the owner target")
            abort(redirect(url_for("evidence_page", name=owner, eid=eid)))
        g.target = t
        return t, ev

    def back(t, eid):
        return redirect(url_for("evidence_page", name=t.name, eid=eid))

    @app.get("/t/<name>/evidence/<eid>")
    @login_required
    def evidence_page(name: str, eid: str):
        t, ev = resolve(name, eid)
        v = request.args.get("v", type=int)
        version = store.load(t.name, eid, v)
        if v and not version:
            abort(404)
        texts = {}
        if version:
            for i, it in enumerate(version.items):
                if it.type == "text":
                    texts[i] = (version.path / it.file).read_text(errors="replace")
        history = store.history(t, eid)
        latest = store.load(t.name, eid)
        return render_template("evidence.html", tab="manual" if ev.kind == "manual" else "auto", ev=ev,
                               version=version, texts=texts, history=history,
                               is_latest=bool(version and latest and version.version == latest.version),
                               used_by=cat.tests_using(eid))

    @app.post("/t/<name>/evidence/<eid>/images")
    @admin_required
    def evidence_add_images(name: str, eid: str):
        t, ev = resolve(name, eid)
        files = request.files.getlist("image")
        captions = request.form.getlist("caption")
        try:
            images = [(f.read(), captions[i] if i < len(captions) else "") for i, f in enumerate(files)]
            v = store.add_images(t, eid, images, g.user["username"])
        except evmod.EvidenceError as e:
            return jsonify(error=str(e)), 400
        return jsonify(ok=True, version=v.version)

    @app.post("/t/<name>/evidence/<eid>/file")
    @admin_required
    def evidence_add_file(name: str, eid: str):
        t, ev = resolve(name, eid)
        f = request.files.get("file")
        try:
            if not f or not f.filename:
                raise evmod.EvidenceError("choose a file")
            store.add_file(t, eid, f.read(), f.filename, request.form.get("caption", ""), g.user["username"])
            flash("File added.")
        except evmod.EvidenceError as e:
            flash(str(e))
        return back(t, eid)

    @app.post("/t/<name>/evidence/<eid>/text")
    @admin_required
    def evidence_add_text(name: str, eid: str):
        t, ev = resolve(name, eid)
        try:
            store.add_text(t, eid, request.form.get("text", ""), request.form.get("caption", ""),
                           g.user["username"])
            flash("Text added.")
        except evmod.EvidenceError as e:
            flash(str(e))
        return back(t, eid)

    @app.post("/t/<name>/evidence/<eid>/items/<int:index>/edit")
    @admin_required
    def evidence_edit_item(name: str, eid: str, index: int):
        t, ev = resolve(name, eid)
        try:
            store.edit_item(t, eid, index, caption=request.form.get("caption"),
                            text=request.form.get("text"), actor=g.user["username"])
            flash("Saved as a new version.")
        except evmod.EvidenceError as e:
            flash(str(e))
        return back(t, eid)

    @app.post("/t/<name>/evidence/<eid>/items/<int:index>/remove")
    @admin_required
    def evidence_remove_item(name: str, eid: str, index: int):
        t, ev = resolve(name, eid)
        try:
            store.remove_item(t, eid, index, g.user["username"])
            flash("Removed in a new version; earlier versions keep the item.")
        except evmod.EvidenceError as e:
            flash(str(e))
        return back(t, eid)

    @app.get("/t/<name>/evidence/<eid>/v/<int:v>/<path:rel>")
    @login_required
    def evidence_file(name: str, eid: str, v: int, rel: str):
        t, ev = resolve(name, eid)
        version = store.load(t.name, eid, v)
        if not version:
            abort(404)
        try:
            path = store.file_path(version, rel)
        except evmod.EvidenceError:
            abort(404)
        item = next((i for i in version.items if i.file == rel), None)
        # Only PNG/JPEG images (checked by magic bytes on upload) and plain text
        # are shown inline; everything else is a download, so an uploaded HTML
        # or SVG file never runs in the tool's origin.
        if item and item.type == "image" and item.mime in ("image/png", "image/jpeg"):
            resp = send_file(path, mimetype=item.mime)
        elif (item and item.type == "text") or rel.endswith(".txt"):
            resp = send_file(path, mimetype="text/plain; charset=utf-8")
        else:
            resp = send_file(path, mimetype="application/octet-stream", as_attachment=True,
                             download_name=(item.name if item and item.name else path.name))
        resp.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox"
        resp.headers["Cache-Control"] = "private, max-age=3600"
        return resp
