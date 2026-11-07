"""AI prompt for one WSTG test on one target (copied to the clipboard).

It holds the criteria, the steps with the tester's verdicts and the commands,
excerpts of the collected evidence, and the existing findings, and asks for a
verdict per step and CVSS vectors for failures, and to end with a JSON
block that `ai_review.py` imports back.

Excerpts: text items and small text files are included (each cut at
PER_FILE chars, the whole prompt at TOTAL chars). Images are listed by
caption. HAR files are not included: they hold cookies and tokens.
"""

from __future__ import annotations

import json

from . import catalog as catmod
from . import evidence as evmod

PER_FILE = 6000
TOTAL = 60000
TEXT_SUFFIXES = (".txt", ".json", ".xml", ".html", ".htm", ".csv", ".md", ".log", ".js", ".tsv", ".yaml")


def _excerpt(version: evmod.Version, budget: list[int]) -> list[str]:
    out = []
    for it in version.items:
        label = it.caption or it.name or it.file
        if it.type == "image":
            out.append(f"   - screenshot: {label} (not included; attach the image if needed)")
            continue
        if it.file.lower().endswith(".har"):
            out.append(f"   - HAR file {it.name or it.file} (not included: holds cookies and tokens)")
            continue
        if it.type == "file" and not it.file.lower().endswith(TEXT_SUFFIXES):
            out.append(f"   - file {it.name or it.file}, {it.size} bytes (binary, not included)")
            continue
        if budget[0] <= 0:
            out.append(f"   - {label}: (not included, prompt size limit reached)")
            continue
        text = (version.path / it.file).read_text(errors="replace")
        cut = min(PER_FILE, budget[0])
        more = f"\n     [... {len(text) - cut} more characters not included]" if len(text) > cut else ""
        budget[0] -= min(len(text), cut)
        body = "\n".join("     " + line for line in text[:cut].splitlines())
        out.append(f"   - {label}:\n{body}{more}")
    return out


def build(*, test: catmod.Test, scenario: catmod.Scenario, target, steps: list[dict],
          store: evmod.Store, findings: list[dict]) -> str:
    budget = [TOTAL]
    lines = [
        "You are reviewing the result of an OWASP WSTG v4.2 test. Decide pass or fail for each step and",
        "for the whole test, using only the criteria and the evidence below. If evidence is missing or a",
        "collection failed, say so: that is never a pass.",
        "",
        f"Test: {test.id} {test.title}",
        f"Target: {target.name} ({target.type})",
        f"OWASP: {test.owasp_url}",
        "",
        f"Overview: {scenario.overview}",
        f"Pass when: {scenario.pass_criteria}",
        f"Fail when: {scenario.fail_criteria}",
    ]
    if scenario.notes:
        lines += ["Notes:"] + [f"- {n}" for n in scenario.notes]
    lines += ["", "Steps (tester verdict in brackets):"]
    seen: set[str] = set()
    for s in steps:
        lines.append(f"{s['n']}. [{s['verdict']}] {s['step'].summary}")
        if s["command"]:
            lines.append(f"   Command: {s['command']}")
        if s["operation"]:
            lines.append(f"   Operation: {s['operation']}")
        if s["step"].ai_task:
            lines.append(f"   YOUR TASK for this step: {s['step'].ai_task}")
        for e in s["evidence"]:
            ev = e["ev"]
            if ev.id in seen:
                lines.append(f"   Evidence {ev.id}: see above")
                continue
            seen.add(ev.id)
            version = store.load(e["owner"], ev.id) if e["owner"] else None
            if not version:
                lines.append(f"   Evidence {ev.id} ({ev.title}): NOT COLLECTED")
                continue
            lines.append(f"   Evidence {ev.id} ({ev.title}), collected {version.created_at} (v{version.version}):")
            if version.meta.get("argv"):
                lines.append(f"     command: {' '.join(version.meta['argv'])} (exit {version.meta.get('exit_code')})")
            lines += _excerpt(version, budget)
    if findings:
        lines += ["", "Findings already recorded for this test:"]
        for f in findings:
            sc = f"{f['cvss']['score']} {f['cvss']['severity']} {f['cvss_vector']}" if f["cvss"] else "not rated"
            lines.append(f"- {f['title']} [{f['status']}] {sc}")
    lines += ["", "Answer with: a verdict per step, an overall verdict, and for each fail the observed problem,",
              "its impact, reproduction steps, and a CVSS 3.1 vector with a short rationale per metric.",
              "",
              "End the answer with this JSON block, filled in (it is imported back into the test tool).",
              "One entry per step. verdict is \"pass\", \"fail\", or \"-\" when the evidence is missing, failed,",
              "or not enough to decide. reason: one or two sentences citing the evidence.",
              "```json",
              json.dumps({"wstg_review": {
                  "test": test.id, "target": target.name, "overall": "pass | fail | -",
                  "summary": "one paragraph",
                  "steps": [{"step": s["n"], "verdict": "pass | fail | -", "reason": "..."} for s in steps]}},
                  indent=2),
              "```"]
    return "\n".join(lines) + "\n"
