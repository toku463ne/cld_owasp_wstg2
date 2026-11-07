"""Import an AI chat answer to the AI prompt and apply its step verdicts.

The prompt (`prompt.py`) asks the AI to end its answer with a JSON block:

    {"wstg_review": {"test": "WSTG-INFO-02", "target": "www.example.com",
                     "overall": "pass" | "fail" | "-", "summary": "...",
                     "steps": [{"step": 1, "verdict": "pass" | "fail" | "-", "reason": "..."}]}}

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
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from . import catalog as catmod
from . import db as dbmod
from . import evidence as evmod
from . import targets as tmod

MAX_ANSWER = 400_000
MAX_REASON = 4000
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

    def to_json(self) -> str:
        return json.dumps({"test": self.test, "target": self.target, "overall": self.overall,
                           "summary": self.summary, "steps": self.steps})


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


def parse(text: str, *, test_id: str, target_name: str, step_count: int) -> Review:
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
                  steps=[steps[n] for n in sorted(steps)])


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
          review: Review, answer: str, actor: str, *, overwrite: bool = False) -> dict:
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
        db.audit(conn, actor, "ai_review.import", target=target.name, test=review.test, review=cur_.lastrowid,
                 applied=sum(r["outcome"] == "applied" for r in results))
    return {"review": review, "results": results}


def latest(db: dbmod.Database, target: tmod.Target, test_id: str) -> dict | None:
    row = db.one("SELECT * FROM ai_reviews WHERE target_id = ? AND test_id = ? ORDER BY id DESC LIMIT 1",
                 (target.id, test_id))
    if not row:
        return None
    review = json.loads(row["review"])
    results = {r["step"]: r for r in json.loads(row["results"])}
    reasons = {s["step"]: s["reason"] for s in review["steps"]}
    return {"id": row["id"], "created_at": row["created_at"], "created_by": row["created_by"],
            "overall": review["overall"], "summary": review["summary"],
            "steps": {n: dict(r, reason=reasons.get(n, "")) for n, r in results.items()}}


def setters(db: dbmod.Database, target: tmod.Target, test_id: str) -> dict[int, str]:
    """{step: updated_by} of the current verdicts."""
    return {r["step"]: r["updated_by"] for r in db.query(
        "SELECT step, updated_by FROM step_verdicts WHERE target_id = ? AND test_id = ?", (target.id, test_id))}
