"""Target pages: target selector, the four main tabs, settings (scope), WSTG pages.

URLs: /t/<target>/ (WSTG index), /t/<target>/findings, /t/<target>/manual,
/t/<target>/auto, /t/<target>/settings, /t/<target>/wstg/<test id>.
"""

from __future__ import annotations

import re

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup, escape

from . import catalog as catmod
from . import db as dbmod
from . import evidence as evmod
from . import findings as fmod
from . import ai_files, ai_review
from . import runner as rmod
from . import targets as tmod
from . import users
from .config import Config
from .web import admin_required, login_required

_TICKS_RE = re.compile(r"`([^`]+)`")
# Spaces that sit right before an inline numbered sub-step ("1. ", "2. " ...).
_NUM_STEP_RE = re.compile(r"(?<=\S) +(?=\d{1,2}\. +[A-Za-z`])")


def ticks(text: str) -> Markup:
    """Escape text and show `code` spans as <code>."""
    return Markup(_TICKS_RE.sub(lambda m: f"<code>{m.group(1)}</code>", str(escape(text or ""))))


def cmdtext(command: str) -> Markup:
    """Show a shell command across lines: break after each top-level `;` (a
    statement separator), leaving `;` inside quotes untouched. A newline is a
    statement separator in bash too, so the command still runs if copied."""
    out, quote = [], None
    for ch in command or "":
        out.append(ch)
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == ";":
            out.append("\n")
    text = re.sub(r";[ \t]*\n[ \t]*", ";\n", "".join(out))
    text = re.sub(r"\n{2,}", "\n", text).strip()
    return Markup(str(escape(text)))


def optext(text: str) -> Markup:
    """Render a step operation: like `ticks`, but also put each embedded command
    (a `code` span with a space) and each inline numbered sub-step on its own
    line, so a long operation is not one wall of text. The line breaks are shown
    by the `.operation` pre-wrap style; the source data is unchanged."""
    esc = _NUM_STEP_RE.sub("\n", str(escape(text or "")))

    def code(m: re.Match) -> str:
        inner = m.group(1)
        return f"\n<code>{inner}</code>\n" if " " in inner else f"<code>{inner}</code>"

    out = re.sub(r"\n{2,}", "\n", _TICKS_RE.sub(code, esc)).strip("\n")
    return Markup(out)


_STATUS_CLASS = {"-": "none", "": "none", "no need": "noneed"}


def status_class(status: str) -> str:
    """CSS class suffix for a status (the display string may contain a space)."""
    return _STATUS_CLASS.get(status, status)


def register(app: Flask, cfg: Config, db: dbmod.Database, cat: catmod.Catalog, store: evmod.Store) -> None:
    app.jinja_env.filters["ticks"] = ticks
    app.jinja_env.filters["optext"] = optext
    app.jinja_env.filters["cmdtext"] = cmdtext
    app.jinja_env.filters["statusclass"] = status_class

    def load_target(name: str) -> tmod.Target:
        t = tmod.get(db, name)
        if not t:
            abort(404)
        g.target = t
        session["target"] = t.name
        return t

    def tests_for(t: tmod.Target) -> list[catmod.Test]:
        return [x for x in cat.tests.values() if t.type in x.target_types]

    def collected(t: tmod.Target) -> dict[str, dict]:
        return ai_files.collected(db, cat, store, t)

    @app.context_processor
    def inject_targets():
        if g.get("user") is None:
            return {}
        return {"all_targets": tmod.list_all(db), "target": g.get("target")}

    @app.get("/")
    @login_required
    def index():
        last = session.get("target")
        if last and tmod.get(db, last):
            return redirect(url_for("wstg_index", name=last))
        all_t = tmod.list_all(db)
        if all_t:
            return redirect(url_for("wstg_index", name=all_t[0].name))
        return render_template("index.html")

    # ---- targets ----------------------------------------------------------

    @app.route("/targets/new", methods=["GET", "POST"])
    @admin_required
    def target_new():
        domains = [t for t in tmod.list_all(db) if t.type == "domain"]
        form = request.form if request.method == "POST" else {
            "type": request.args.get("type", "fqdn"), "parent": request.args.get("parent", "")}
        if request.method == "POST":
            try:
                t = tmod.create(db, cfg, form.get("name", ""), form.get("type", ""),
                                parent=form.get("parent") or None, description=form.get("description", ""),
                                actor=g.user["username"])
                session["target"] = t.name
                flash(f"Target {t.name} created. Set its scope record before running commands.")
                return redirect(url_for("target_settings", name=t.name))
            except tmod.TargetError as e:
                flash(str(e))
        return render_template("target_new.html", domains=domains, form=form)

    @app.route("/t/<name>/settings", methods=["GET", "POST"])
    @login_required
    def target_settings(name: str):
        t = load_target(name)
        if request.method == "POST":
            if not users.can_write(g.user):
                abort(403)
            try:
                tmod.update_description(db, t, request.form.get("description", ""), g.user["username"])
                tmod.update_scope(
                    db, t, allowed_hosts=request.form.get("allowed_hosts", ""),
                    allowed_ports=request.form.get("allowed_ports", ""),
                    base_url=request.form.get("base_url", ""),
                    authorization_ref=request.form.get("authorization_ref", ""),
                    valid_from=request.form.get("valid_from", ""),
                    valid_until=request.form.get("valid_until", ""), actor=g.user["username"])
                flash("Saved.")
                return redirect(url_for("target_settings", name=t.name))
            except tmod.TargetError as e:
                flash(str(e))
            t = load_target(name)
        scope = tmod.get_scope(db, t)
        return render_template("target_settings.html", tab="settings", scope=scope,
                               problems=tmod.scope_problems(scope),
                               evidence_dir=tmod.evidence_dir(cfg, t))

    # ---- main tabs --------------------------------------------------------

    @app.get("/t/<name>/")
    @login_required
    def wstg_index(name: str):
        t = load_target(name)
        vs = tmod.verdicts(db, t)
        have = collected(t)
        reviews = tmod.test_reviews(db, t)
        rows = []
        prompts_dir = ai_files.folder(cfg, t) / "prompts"
        for test in tests_for(t):
            sc = cat.scenarios.get(test.id)
            has_ev = any(e.id in have for e in cat.evidence_for(test.id))
            if test.merged_into:
                st = None
            else:
                st = reviews.get(test.id, {}).get("override") \
                    or tmod.status(len(sc.steps) if sc else 0, vs.get(test.id, {}), has_ev)
            rows.append({"test": test, "scenario": sc, "status": st,
                         "evidence": ai_files.evidence_state(cat, test.id, have) if sc else None,
                         "prompt": sc is not None and (prompts_dir / f"{test.id}.md").exists()})
        counts = {s: sum(1 for r in rows if r["status"] == s) for s in tmod.STATUSES}
        ev_counts = {s: sum(1 for r in rows if r["evidence"] and r["evidence"]["state"] == s)
                     for s in ("complete", "partial", "none")}
        scope_problems = tmod.scope_problems(tmod.get_scope(db, t))
        return render_template("wstg_index.html", tab="index", rows=rows, counts=counts,
                               scope_problems=scope_problems, ai_folder=ai_files.folder(cfg, t),
                               ev_counts=ev_counts,
                               ai_answers=len(ai_files.answer_files(cfg, t)),
                               ai_prompts=len(ai_files.tests_with_scenarios(cat, t)))

    @app.get("/t/<name>/manual")
    @login_required
    def manual_tab(name: str):
        t = load_target(name)
        have = collected(t)
        rows = []
        for e in cat.evidence.values():
            owner = tmod.evidence_owner(t, e.target_type)
            if e.kind == "manual" and owner:
                rows.append({"ev": e, "owner": owner, "row": have.get(e.id), "used_by": cat.tests_using(e.id)})
        rows.sort(key=lambda r: (r["owner"] != t.name, r["used_by"][:1], r["ev"].id))
        return render_template("manual_tab.html", tab="manual", rows=rows)

    @app.get("/t/<name>/auto")
    @login_required
    def auto_tab(name: str):
        t = load_target(name)
        have = {k: v for k, v in collected(t).items() if v["owner"] == t.name}
        failed = {r["evidence_id"]: r for r in db.query(
            "SELECT * FROM evidence_versions WHERE target_id = ? AND status = 'failed' ORDER BY version", (t.id,))}
        evs = [e for e in cat.evidence.values() if e.kind == "auto" and e.target_type == t.type]
        job = rmod.last_job(db, t)
        items = rmod.job_items(db, job["id"]) if job else []
        active = bool(job and job["status"] in rmod.ACTIVE)
        waiting = bool(job and job["status"] == "queued")
        return render_template("auto_tab.html", tab="auto", evidence=evs, cat=cat, have=have, failed=failed,
                               job=job, items=items, active=active, waiting=waiting,
                               stale=bool(job and rmod.stale(db, cfg, job)),
                               light_count=len(rmod.plan(cat, t, "light")), full_count=len(rmod.plan(cat, t, "full")),
                               scope_problems=tmod.scope_problems(tmod.get_scope(db, t)))

    @app.post("/t/<name>/auto/collect")
    @admin_required
    def auto_collect(name: str):
        t = load_target(name)
        try:
            job = rmod.enqueue(db, cat, t, request.form.get("mode", "light"), g.user["username"])
            flash(f"Job {job} queued. Evidence that is already collected is skipped.")
        except rmod.RunError as e:
            flash(str(e))
        return redirect(url_for("auto_tab", name=t.name))

    @app.post("/t/<name>/auto/collect/<eid>")
    @admin_required
    def auto_collect_one(name: str, eid: str):
        t = load_target(name)
        force = bool(request.form.get("force"))
        try:
            job = rmod.enqueue(db, cat, t, "light", g.user["username"], evidence_id=eid, force=force)
            flash(f"Job {job} queued: {eid}" + (" (collect again; earlier versions are kept)." if force else "."))
        except rmod.RunError as e:
            flash(str(e))
        back = request.form.get("back")
        if back == "evidence":
            return redirect(url_for("evidence_page", name=t.name, eid=eid))
        return redirect(url_for("auto_tab", name=t.name))

    @app.post("/t/<name>/auto/jobs/<int:job_id>/cancel")
    @admin_required
    def auto_cancel(name: str, job_id: int):
        t = load_target(name)
        if not db.one("SELECT 1 FROM jobs WHERE id = ? AND target_id = ?", (job_id, t.id)):
            abort(404)
        rmod.cancel(db, job_id, g.user["username"])
        flash(f"Job {job_id}: stop requested. The running command is killed within a few seconds.")
        return redirect(url_for("auto_tab", name=t.name))

    @app.post("/t/<name>/auto/jobs/<int:job_id>/items/<int:seq>/stop")
    @admin_required
    def auto_stop_item(name: str, job_id: int, seq: int):
        t = load_target(name)
        if not db.one("SELECT 1 FROM jobs WHERE id = ? AND target_id = ?", (job_id, t.id)):
            abort(404)
        if rmod.stop_item(db, job_id, seq, g.user["username"]):
            flash(f"Job {job_id}: stopping item {seq}; the job goes on with the next item.")
        else:
            flash(f"Job {job_id}: item {seq} is not running.")
        return redirect(url_for("auto_tab", name=t.name))

    # ---- WSTG page --------------------------------------------------------

    @app.get("/t/<name>/wstg/<test_id>")
    @login_required
    def wstg_page(name: str, test_id: str):
        t = load_target(name)
        test = cat.tests.get(test_id)
        if not test:
            abort(404)
        if test.merged_into:
            flash(f"{test.id} is merged into {test.merged_into} in WSTG v4.2.")
            return redirect(url_for("wstg_page", name=t.name, test_id=test.merged_into))
        sc = cat.scenarios.get(test_id)
        have = collected(t)
        vs = tmod.verdicts(db, t, test_id).get(test_id, {})
        steps = ai_files.steps_for(cfg, db, cat, store, t, test_id, have)
        has_ev = any(e.id in have for e in cat.evidence_for(test_id))
        review = tmod.test_review(db, t, test_id)
        computed = tmod.status(len(steps), vs, has_ev) if sc else "-"
        st_value = review["override"] or computed
        findings = fmod.list_for(db, t, test_id)
        ai_prompt = ai_files.build_prompt(cfg, db, cat, store, t, test_id, steps) if sc else ""
        setters = ai_review.setters(db, t, test_id)
        for s in steps:
            s["by_ai"] = setters.get(s["n"], "").startswith(ai_review.AI_PREFIX)
        return render_template("wstg_page.html", tab="index", test=test, scenario=sc, steps=steps,
                               status=st_value, computed=computed, status_options=tmod.STATUS_OVERRIDES,
                               step_verdict_options=("-", *tmod.VERDICTS),
                               applicable=t.type in test.target_types,
                               findings=findings, ai_prompt=ai_prompt, review=review,
                               ai=ai_review.latest(db, t, test_id) if sc else None)

    @app.post("/t/<name>/wstg/<test_id>/status")
    @admin_required
    def wstg_status(name: str, test_id: str):
        t = load_target(name)
        if test_id not in cat.tests or cat.tests[test_id].merged_into:
            abort(404)
        status = request.form.get("status", "")
        try:
            tmod.set_status_override(db, t, test_id, status, g.user["username"])
        except tmod.TargetError as e:
            flash(str(e))
        else:
            flash(f"{test_id}: status set to \"{status}\"." if status
                  else f"{test_id}: status back to automatic (computed from steps).")
        return redirect(url_for("wstg_page", name=t.name, test_id=test_id))

    @app.post("/t/<name>/wstg/<test_id>/tester-review")
    @admin_required
    def wstg_tester_review(name: str, test_id: str):
        t = load_target(name)
        if test_id not in cat.tests or cat.tests[test_id].merged_into:
            abort(404)
        tmod.set_tester_review(db, t, test_id, request.form.get("review", ""), g.user["username"])
        flash(f"{test_id}: tester review saved.")
        return redirect(url_for("wstg_page", name=t.name, test_id=test_id) + "#tester-review")

    @app.post("/t/<name>/wstg/<test_id>/ai-review")
    @admin_required
    def wstg_ai_import(name: str, test_id: str):
        t = load_target(name)
        sc = cat.scenarios.get(test_id)
        if not sc:
            abort(404)
        answer = request.form.get("answer", "")
        try:
            review = ai_review.parse(answer, test_id=test_id, target_name=t.name, step_count=len(sc.steps),
                                     kinds=sc.finding_kinds or tuple(cat.finding_kinds))
        except ai_review.ReviewError as e:
            flash(f"AI answer not imported: {e}")
            return redirect(url_for("wstg_page", name=t.name, test_id=test_id) + "#ai-review")
        out = ai_review.apply(db, store, cat, t, review, answer, g.user["username"],
                              overwrite=bool(request.form.get("overwrite")),
                              create_findings=bool(request.form.get("findings")))
        counts: dict[str, int] = {}
        for r in out["results"]:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        msg = "AI review imported: " + ", ".join(f"{v} {k}" for k, v in counts.items())
        if review.findings:
            msg += f"; {len(review.findings)} finding(s) proposed, {len(out['findings_created'])} created"
        flash(msg)
        return redirect(url_for("wstg_page", name=t.name, test_id=test_id) + "#ai-review")

    @app.post("/t/<name>/wstg/<test_id>/ai-review/<int:review_id>/findings/<int:index>")
    @admin_required
    def wstg_ai_finding(name: str, test_id: str, review_id: int, index: int):
        t = load_target(name)
        if not db.one("SELECT 1 FROM ai_reviews WHERE id = ? AND target_id = ? AND test_id = ?",
                      (review_id, t.id, test_id)):
            abort(404)
        try:
            fid, new = ai_review.create_finding(db, t, review_id, index, g.user["username"])
        except (ai_review.ReviewError, fmod.FindingError) as e:
            flash(f"Finding not created: {e}")
            return redirect(url_for("wstg_page", name=t.name, test_id=test_id) + "#ai-review")
        flash("Finding created from the AI review; check and edit it." if new
              else "A finding with this title already exists.")
        return redirect(url_for("finding_page", name=t.name, fid=fid))

    @app.post("/t/<name>/wstg/<test_id>/ai-prompt/save")
    @admin_required
    def wstg_ai_prompt_save(name: str, test_id: str):
        t = load_target(name)
        if test_id not in ai_files.tests_with_scenarios(cat, t):
            abort(404)
        path = ai_files.save_prompts(cfg, db, cat, store, t, [test_id])["saved"][0]
        flash(f"AI prompt saved to {path}")
        return redirect(url_for("wstg_page", name=t.name, test_id=test_id))

    @app.post("/t/<name>/ai/prompts")
    @admin_required
    def ai_prompts_save(name: str):
        t = load_target(name)
        evidence = request.form.get("evidence", "complete")
        existing = request.form.get("existing", "skip")
        if evidence not in ai_files.EVIDENCE_FILTERS or existing not in ai_files.EXISTING:
            abort(400)
        res = ai_files.save_prompts(cfg, db, cat, store, t, evidence=evidence, existing=existing)
        flash(f"AI prompts: {ai_files.summary(res)} in {ai_files.folder(cfg, t) / 'prompts'}")
        return redirect(url_for("wstg_index", name=t.name) + "#ai-bulk")

    @app.post("/t/<name>/ai/answers")
    @admin_required
    def ai_answers_import(name: str):
        t = load_target(name)
        results = ai_files.import_answers(cfg, db, cat, store, t, g.user["username"],
                                          overwrite=bool(request.form.get("overwrite")),
                                          create_findings=bool(request.form.get("findings")))
        if not results:
            flash(f"No answer files in {ai_files.folder(cfg, t) / 'answers'}")
        for r in results:
            flash(f"{r['file']}: {r['status']}" + (f" ({r['message']})" if r["message"] else ""))
        return redirect(url_for("wstg_index", name=t.name) + "#ai-bulk")

    @app.post("/t/<name>/wstg/<test_id>/reset")
    @admin_required
    def wstg_reset(name: str, test_id: str):
        t = load_target(name)
        if test_id not in cat.scenarios:
            abort(404)
        out = ai_review.reset_test(db, t, test_id, g.user["username"])
        flash(f"{test_id} reset: {out['verdicts']} step verdict(s) and {out['ai_reviews']} AI review(s) removed."
              " Evidence and findings are kept.")
        return redirect(url_for("wstg_page", name=t.name, test_id=test_id))

    @app.post("/t/<name>/wstg/<test_id>/steps/<int:n>")
    @admin_required
    def wstg_step_verdict(name: str, test_id: str, n: int):
        t = load_target(name)
        sc = cat.scenarios.get(test_id)
        if not sc or not 1 <= n <= len(sc.steps):
            abort(404)
        verdict = "-" if "reset" in request.form else request.form.get("verdict", "-")
        try:
            tmod.set_verdict(db, t, test_id, n, verdict, g.user["username"])
        except tmod.TargetError as e:
            flash(str(e))
        return redirect(url_for("wstg_page", name=t.name, test_id=test_id) + f"#step-{n}")
