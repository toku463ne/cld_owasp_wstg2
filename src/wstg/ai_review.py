"""Import an AI chat answer to the AI prompt and apply its step verdicts.

The prompt (`prompt.py`) asks the AI to end its answer with a JSON block:

    {"wstg_review": {"test": "WSTG-INFO-02", "target": "www.example.com",
                     "overall": "pass" | "fail" | "-", "summary": "...",
                     "steps": [{"step": 1, "verdict": "pass" | "fail" | "-", "reason": "..."}],
                     "findings": [{"title": "...", "steps": [2], "summary": "...", "impact": "...",
                                   "reproduction": "...", "cvss_vector": "CVSS:3.1/...",
                                   "cvss_rationale": "..."}]}}

`parse()` finds that block in the pasted answer (the last ```json block, or
the whole text) and validates it. `apply()` sets the step verdicts, with
these rules:

- "-" (no decision) never changes a step.
- A "pass" is refused when an evidence of the step is missing or its last
  collection failed: a missing or failed collection is never a pass.
- A verdict set by a tester (not by an earlier AI import) is kept unless
  `overwrite` is set.
- Applied verdicts are recorded as set by "ai:<user>", so the page can tell
  them apart, and every import is stored with its per-step outcome.

Proposed findings are kept with the review. `create_finding()` turns one into a
finding (created by "ai:<user>") unless it duplicates an existing one: the AI's
"same_as" (an existing finding id), the same kind and subject anywhere on the
target, or the same title on the same test. `apply(create_findings=True)`
creates all of them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from . import catalog as catmod
from . import cvss
from . import findings as fmod
from . import db as dbmod
from . import evidence as evmod
from . import targets as tmod

MAX_ANSWER = 400_000
MAX_REASON = 4000
MAX_FINDINGS = 20
FINDING_TEXT = ("summary", "impact", "reproduction", "cvss_rationale")
AI_PREFIX = "ai:"
FENCE_RE = re.compile(r"```[a-zA-Z]*\s*\n(.*?)```", re.S)


class ReviewError(ValueError):
    pass


@dataclass
class Review:
    test: str
    target: str
    overall: str
    summary: str
    steps: list[dict]          # [{"step": n, "verdict": v, "reason": r}]
    findings: list[dict] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({"test": self.test, "target": self.target, "overall": self.overall,
                           "summary": self.summary, "steps": self.steps, "findings": self.findings})


def _candidates(text: str):
    for block in reversed(FENCE_RE.findall(text)):
        yield block
    yield text
    i, j = text.find("{"), text.rfind("}")
    if 0 <= i < j:
        yield text[i:j + 1]


def _find(text: str) -> dict:
    for chunk in _candidates(text):
        try:
            data = json.loads(chunk)
        except ValueError:
            continue
        if isinstance(data, dict) and isinstance(data.get("wstg_review"), dict):
            return data["wstg_review"]
        if isinstance(data, dict) and "steps" in data:
            return data
    raise ReviewError("no review JSON found: the answer must contain the ```json block the prompt asks for"
                      ' ({"wstg_review": {...}})')


def _verdict(v, where: str) -> str:
    v = "-" if v is None else str(v).strip().lower()
    if v in ("", "none", "n/a", "unknown", "undecided"):
        v = "-"
    if v not in ("pass", "fail", "-"):
        raise ReviewError(f"{where}: verdict must be pass, fail, or - (got {v!r})")
    return v


def parse(text: str, *, test_id: str, target_name: str, step_count: int,
          kinds: tuple[str, ...] | None = None) -> Review:
    """`kinds`: finding kinds the scenario allows (None = any)."""
    text = (text or "").strip()
    if not text:
        raise ReviewError("paste the AI answer first")
    if len(text) > MAX_ANSWER:
        raise ReviewError(f"the answer is longer than {MAX_ANSWER} characters")
    d = _find(text)
    test = str(d.get("test") or "").strip().upper()
    if test and test != test_id:
        raise ReviewError(f"this review is for {test}, not {test_id}")
    target = str(d.get("target") or "").strip().lower().rstrip(".")
    if target and target != target_name:
        raise ReviewError(f"this review is for target {target}, not {target_name}")
    raw_steps = d.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ReviewError("the review has no steps")
    steps: dict[int, dict] = {}
    for i, s in enumerate(raw_steps):
        if not isinstance(s, dict):
            raise ReviewError(f"steps[{i}] is not an object")
        try:
            n = int(s.get("step"))
        except (TypeError, ValueError):
            raise ReviewError(f"steps[{i}]: step must be a number") from None
        if not 1 <= n <= step_count:
            raise ReviewError(f"steps[{i}]: step {n} does not exist ({test_id} has {step_count} steps)")
        if n in steps:
            raise ReviewError(f"step {n} appears twice")
        steps[n] = {"step": n, "verdict": _verdict(s.get("verdict"), f"step {n}"),
                    "reason": str(s.get("reason") or "").strip()[:MAX_REASON]}
    return Review(test=test_id, target=target_name, overall=_verdict(d.get("overall"), "overall"),
                  summary=str(d.get("summary") or "").strip()[:MAX_REASON],
                  steps=[steps[n] for n in sorted(steps)],
                  findings=_findings(d.get("findings"), step_count, kinds))


def _findings(raw, step_count: int, kinds=None) -> list[dict]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise ReviewError("findings must be a list")
    if len(raw) > MAX_FINDINGS:
        raise ReviewError(f"more than {MAX_FINDINGS} findings")
    out = []
    for i, f in enumerate(raw):
        if not isinstance(f, dict):
            raise ReviewError(f"findings[{i}] is not an object")
        title = str(f.get("title") or "").strip()
        if not title:
            raise ReviewError(f"findings[{i}] has no title")
        item = {"title": title[:300], "note": ""}
        kind = str(f.get("kind") or "").strip().lower()
        if kind in ("", "none", "other"):
            kind = ""
        elif kinds is not None and kind not in kinds:
            item["note"] = f"kind {kind[:60]!r} is not one of this test's kinds; checked by title only. "
            kind = ""
        item["kind"] = kind
        item["subject"] = fmod.normalize_subject(str(f.get("subject") or ""))[:300] if kind else ""
        if kind and not item["subject"]:
            item["kind"], item["note"] = "", "kind without a subject; checked by title only. "
        same = f.get("same_as")
        try:
            item["same_as"] = int(str(same).lstrip("#")) if same not in (None, "", "null") else None
        except ValueError:
            item["same_as"] = None
        for k in FINDING_TEXT:
            item[k] = str(f.get(k) or "").strip()[:fmod.MAX_TEXT]
        st = f.get("steps") or []
        item["steps"] = sorted({int(x) for x in (st if isinstance(st, list) else [st])
                                if str(x).strip().isdigit() and 1 <= int(x) <= step_count})
        vector = str(f.get("cvss_vector") or "").strip()
        try:
            item["cvss_vector"] = cvss.normalize(vector) if vector else ""
        except cvss.CvssError as e:
            item["cvss_vector"] = ""
            item["note"] += f"CVSS vector dropped ({e}): {vector[:120]}"
        item["note"] = item["note"].strip()
        out.append(item)
    return out


def match_finding(db: dbmod.Database, target: tmod.Target, test_id: str, f: dict) -> tuple[int | None, str]:
    """The existing finding a proposal duplicates, and why: the AI's same_as, the
    same kind and subject on the target (any test), or the same title on the test."""
    if f.get("same_as") and fmod.get(db, target, f["same_as"]):
        return f["same_as"], "same_as"
    if (fid := fmod.find_by_key(db, target, f.get("kind", ""), f.get("subject", ""))) is not None:
        return fid, "kind and subject"
    row = db.one("SELECT id FROM findings WHERE target_id = ? AND test_id = ? AND lower(title) = lower(?)",
                 (target.id, test_id, f["title"]))
    return (row["id"], "title") if row else (None, "")


def create_finding(db: dbmod.Database, target: tmod.Target, review_id: int, index: int, actor: str
                   ) -> tuple[int, bool]:
    """Create finding `index` of an imported review. Returns (finding id, created);
    created is False when the proposal duplicates an existing finding (match_finding)."""
    row = db.one("SELECT * FROM ai_reviews WHERE id = ? AND target_id = ?", (review_id, target.id))
    if not row:
        raise ReviewError("no such AI review")
    props = json.loads(row["review"]).get("findings") or []
    if not 0 <= index < len(props):
        raise ReviewError("no such proposed finding")
    f = props[index]
    fid, _ = match_finding(db, target, row["test_id"], f)
    if fid is not None:
        return fid, False
    data = {k: f.get(k, "") for k in ("title", "summary", "impact", "reproduction", "cvss_vector",
                                      "cvss_rationale", "kind", "subject")}
    if f.get("note"):
        data["cvss_rationale"] = (data["cvss_rationale"] + "\n\n" + f["note"]).strip()
    data["status"] = "open"
    try:
        return fmod.create(db, target, row["test_id"], data, AI_PREFIX + actor), True
    except fmod.FindingError as e:
        if e.existing is not None:       # created meanwhile
            return e.existing, False
        raise


def missing_evidence(store: evmod.Store, cat: catmod.Catalog, target: tmod.Target, step: catmod.Step) -> list[str]:
    """Evidence of a step without a usable (complete) version."""
    out = []
    for eid in step.evidence:
        ev = cat.evidence[eid]
        owner = tmod.evidence_owner(target, ev.target_type)
        if not owner or not store.load(owner, eid):
            out.append(eid)
    return out


def apply(db: dbmod.Database, store: evmod.Store, cat: catmod.Catalog, target: tmod.Target,
          review: Review, answer: str, actor: str, *, overwrite: bool = False,
          create_findings: bool = False) -> dict:
    sc = cat.scenarios[review.test]
    current = {r["step"]: r for r in db.query(
        "SELECT step, verdict, updated_by FROM step_verdicts WHERE target_id = ? AND test_id = ?",
        (target.id, review.test))}
    results = []
    for s in review.steps:
        n, v = s["step"], s["verdict"]
        cur = current.get(n)
        res = {"step": n, "proposed": v, "before": cur["verdict"] if cur else "-"}
        if v == "-":
            res.update(outcome="no decision", note="the AI did not decide; step unchanged")
        elif cur and cur["verdict"] == v:
            res.update(outcome="unchanged", note="already " + v)
        elif v == "pass" and (missing := missing_evidence(store, cat, target, sc.steps[n - 1])):
            res.update(outcome="refused", note="evidence missing or failed: " + ", ".join(missing))
        elif cur and not cur["updated_by"].startswith(AI_PREFIX) and not overwrite:
            res.update(outcome="kept", note=f"tester verdict {cur['verdict']} kept (by {cur['updated_by']})")
        else:
            tmod.set_verdict(db, target, review.test, n, v, AI_PREFIX + actor)
            res.update(outcome="applied", note="")
        results.append(res)
    with db.tx() as conn:
        cur_ = conn.execute(
            "INSERT INTO ai_reviews (target_id, test_id, created_at, created_by, answer, review, results)"
            " VALUES (?,?,?,?,?,?,?)",
            (target.id, review.test, dbmod.utcnow(), actor, answer, review.to_json(), json.dumps(results)))
        review_id = cur_.lastrowid
        db.audit(conn, actor, "ai_review.import", target=target.name, test=review.test, review=review_id,
                 applied=sum(r["outcome"] == "applied" for r in results))
    created = []
    if create_findings:
        for i in range(len(review.findings)):
            fid, new = create_finding(db, target, review_id, i, actor)
            if new:
                created.append(fid)
    return {"review": review, "results": results, "id": review_id, "findings_created": created}


def latest(db: dbmod.Database, target: tmod.Target, test_id: str) -> dict | None:
    row = db.one("SELECT * FROM ai_reviews WHERE target_id = ? AND test_id = ? ORDER BY id DESC LIMIT 1",
                 (target.id, test_id))
    if not row:
        return None
    review = json.loads(row["review"])
    results = {r["step"]: r for r in json.loads(row["results"])}
    reasons = {s["step"]: s["reason"] for s in review["steps"]}
    proposals = []
    for i, f in enumerate(review.get("findings") or []):
        fid, why = match_finding(db, target, test_id, f)
        proposals.append(dict(f, index=i, finding=fid, match=why, cvss=cvss.try_score(f["cvss_vector"])))
    return {"id": row["id"], "created_at": row["created_at"], "created_by": row["created_by"],
            "overall": review["overall"], "summary": review["summary"], "findings": proposals,
            "answer": row["answer"],
            "steps": {n: dict(r, reason=reasons.get(n, "")) for n, r in results.items()}}


def setters(db: dbmod.Database, target: tmod.Target, test_id: str) -> dict[int, str]:
    """{step: updated_by} of the current verdicts."""
    return {r["step"]: r["updated_by"] for r in db.query(
        "SELECT step, updated_by FROM step_verdicts WHERE target_id = ? AND test_id = ?", (target.id, test_id))}
