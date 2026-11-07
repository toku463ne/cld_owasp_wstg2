"""AI prompts and answers as files in the evidence folder, for AI agents.

Per target:

    <evidence root>/<target>/_ai/
        README.md                 what an agent has to do (written with the prompts)
        prompts/WSTG-INFO-02.md   the AI prompt of each test (same text as "Copy AI prompt")
        answers/WSTG-INFO-02.json the answer, written by an AI agent or saved from an AI chat

An answer file holds the JSON object the prompt asks for ({"wstg_review": ...})
or the whole answer text ending with that ```json block. `import_answers()`
imports every answer file like the "Import an AI answer" form on the WSTG page;
a file whose content was already imported is skipped. ("_ai" cannot clash with
an evidence ID: those use lower-case letters, digits, and "-" only.)
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from . import ai_review
from . import analysis
from . import catalog as catmod
from . import db as dbmod
from . import evidence as evmod
from . import findings as fmod
from . import prompt
from . import targets as tmod
from .config import Config

FOLDER = "_ai"
TEST_FILE_RE = re.compile(r"^(WSTG-[A-Z]+-\d+)\.json$")
MAX_FILE = ai_review.MAX_ANSWER

README = """# AI review of {target}

Each file in `prompts/` is the AI prompt of one OWASP WSTG test on {target}
(the same text as "Copy AI prompt" on the WSTG page, saved {saved}).

For each prompt file `prompts/WSTG-XXXX-NN.md`:

1. Skip it when `answers/WSTG-XXXX-NN.json` already exists and is newer than the prompt.
2. Read the prompt and follow it. You may read the evidence folders it lists for
   more detail. Do not read or copy `*.har` files: they hold cookies and tokens.
   Do not send any request to the target or its hosts.
3. A missing or failed collection is never a pass: use "-" when the evidence is
   missing or not enough to decide.
4. Write the answer to `answers/WSTG-XXXX-NN.json` (same name, `.json`): only the
   JSON object the prompt asks for, `{{"wstg_review": {{...}}}}`, filled in, as valid
   JSON without code fences or other text. Keep "test" and "target" as given; one
   entry per step; "findings" with full CVSS 3.1 vectors, or [] when there is none.
5. Do not change anything else in the evidence folders.

Then import the answers: the "Import AI answers" button on the WSTG index tab, or
`uv run wstg ai-import {target}`.
"""


def folder(cfg: Config, target: tmod.Target) -> Path:
    return tmod.evidence_dir(cfg, target) / FOLDER


def collected(db: dbmod.Database, cat: catmod.Catalog, store: evmod.Store, t: tmod.Target) -> dict[str, dict]:
    """{evidence_id: newest complete version row} visible from t (own + parent domain)."""
    out = {}
    parent = tmod.get(db, t.parent_name) if t.parent_name else None
    if parent:
        out.update({k: dict(v, owner=parent.name) for k, v in store.latest_rows(parent).items()
                    if cat.evidence.get(k) and cat.evidence[k].target_type == "domain"})
    out.update({k: dict(v, owner=t.name) for k, v in store.latest_rows(t).items()})
    return out


def evidence_paths(cfg: Config, cat: catmod.Catalog, t: tmod.Target) -> dict[str, str]:
    out = {}
    for e in cat.evidence.values():
        owner = tmod.evidence_owner(t, e.target_type)
        if owner:
            out[e.id] = str(tmod.evidence_dir(cfg, owner) / e.id / "latest")
    return out


def steps_for(cfg: Config, db: dbmod.Database, cat: catmod.Catalog, store: evmod.Store,
              t: tmod.Target, test_id: str, have: dict | None = None) -> list[dict]:
    """The steps of a scenario as the WSTG page and the AI prompt show them
    (rendered commands, auto-run output, evidence rows, verdicts)."""
    sc = cat.scenarios.get(test_id)
    if not sc:
        return []
    values = tmod.placeholder_values(cfg, t, tmod.get_scope(db, t))
    ev_paths = evidence_paths(cfg, cat, t)
    have = collected(db, cat, store, t) if have is None else have
    vs = tmod.verdicts(db, t, test_id).get(test_id, {})
    cache_dir = folder(cfg, t).parent / ".analysis"
    steps = []
    for i, st in enumerate(sc.steps, 1):
        command = catmod.render(st.command, values, ev_paths)
        steps.append({
            "n": i, "step": st, "verdict": vs.get(i, "-"),
            "auto": analysis.run(cache_dir, st.command, command, ev_paths) if st.auto_run else None,
            "command": command,
            "operation": catmod.render(st.operation, values, ev_paths),
            "evidence": [{"ev": cat.evidence[eid], "owner": tmod.evidence_owner(t, cat.evidence[eid].target_type),
                          "row": have.get(eid),
                          "used_by": [x for x in cat.tests_using(eid) if x != test_id]}
                         for eid in st.evidence],
        })
    return steps


def build_prompt(cfg: Config, db: dbmod.Database, cat: catmod.Catalog, store: evmod.Store,
                 t: tmod.Target, test_id: str, steps: list[dict] | None = None, *,
                 for_file: bool = False) -> str:
    test, sc = cat.tests[test_id], cat.scenarios[test_id]
    steps = steps_for(cfg, db, cat, store, t, test_id) if steps is None else steps
    text = prompt.build(test=test, scenario=sc, target=t, steps=steps, store=store,
                        findings=fmod.list_for(db, t, test_id))
    if not for_file:
        return text
    lines = ["", "Evidence folders on this host (latest complete version; do not read *.har files):"]
    seen = set()
    for s in steps:
        for e in s["evidence"]:
            if e["owner"] and e["ev"].id not in seen:
                seen.add(e["ev"].id)
                version = store.load(e["owner"], e["ev"].id)
                lines.append(f"- {e['ev'].id}: {version.path if version else 'not collected'}")
    answer = folder(cfg, t) / "answers" / f"{test_id}.json"
    lines += ["", f"Write the JSON object above, filled in, to {answer}"]
    return text + "\n".join(lines) + "\n"


def tests_with_scenarios(cat: catmod.Catalog, t: tmod.Target) -> list[str]:
    return [tid for tid in cat.scenarios if t.type in cat.tests[tid].target_types]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def save_prompts(cfg: Config, db: dbmod.Database, cat: catmod.Catalog, store: evmod.Store,
                 t: tmod.Target, test_ids: list[str] | None = None) -> list[Path]:
    """Write prompts/<test>.md for the given tests (default: every test with a
    scenario for this target type) and README.md. Returns the prompt paths."""
    base = folder(cfg, t)
    have = collected(db, cat, store, t)
    out = []
    for tid in test_ids or tests_with_scenarios(cat, t):
        steps = steps_for(cfg, db, cat, store, t, tid, have)
        path = base / "prompts" / f"{tid}.md"
        _write(path, build_prompt(cfg, db, cat, store, t, tid, steps, for_file=True))
        out.append(path)
    (base / "answers").mkdir(mode=0o700, parents=True, exist_ok=True)
    _write(base / "README.md", README.format(target=t.name, saved=dbmod.utcnow()))
    return out


def answer_files(cfg: Config, t: tmod.Target) -> list[Path]:
    d = folder(cfg, t) / "answers"
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if TEST_FILE_RE.match(p.name) and p.is_file() and not p.is_symlink())


def import_answers(cfg: Config, db: dbmod.Database, cat: catmod.Catalog, store: evmod.Store,
                   t: tmod.Target, actor: str, *, overwrite: bool = False,
                   create_findings: bool = False) -> list[dict]:
    """Import every answers/WSTG-*.json. One result per file:
    {"file", "test", "status": imported | skipped | error, "message"}."""
    results = []
    for path in answer_files(cfg, t):
        tid = TEST_FILE_RE.match(path.name).group(1)
        res = {"file": path.name, "test": tid, "status": "error", "message": ""}
        results.append(res)
        sc = cat.scenarios.get(tid)
        if not sc or t.type not in cat.tests[tid].target_types:
            res["message"] = f"{tid} has no scenario for {t.type} targets"
            continue
        if path.stat().st_size > MAX_FILE:
            res["message"] = f"larger than {MAX_FILE} bytes"
            continue
        text = path.read_text(errors="replace")
        last = db.one("SELECT answer FROM ai_reviews WHERE target_id = ? AND test_id = ? ORDER BY id DESC LIMIT 1",
                      (t.id, tid))
        if last and last["answer"] == text:
            res.update(status="skipped", message="already imported")
            continue
        try:
            review = ai_review.parse(text, test_id=tid, target_name=t.name, step_count=len(sc.steps))
        except ai_review.ReviewError as e:
            res["message"] = str(e)
            continue
        out = ai_review.apply(db, store, cat, t, review, text, actor, overwrite=overwrite,
                              create_findings=create_findings)
        counts: dict[str, int] = {}
        for r in out["results"]:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        msg = ", ".join(f"{v} {k}" for k, v in counts.items())
        if review.findings:
            msg += f"; {len(review.findings)} finding(s) proposed"
            if create_findings:
                msg += f", {len(out['findings_created'])} created"
        res.update(status="imported", message=msg)
    return results
