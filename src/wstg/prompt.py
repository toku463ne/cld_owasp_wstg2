"""AI prompt for one WSTG test on one target (copied to the clipboard).

It holds the criteria, the steps with the tester's verdicts and the commands,
excerpts of the collected evidence, and the existing findings, and asks for a
verdict per step and CVSS vectors for failures, and to end with a JSON
block that `ai_review.py` imports back.

Excerpts: text items and small text files are included (each cut at
PER_FILE chars, the whole prompt at TOTAL chars). Images are listed by
caption. HAR files are summarized without values (cookies and tokens removed),
and the output of auto-run commands that read HAR files is left out for the
same reason. Outputs of other auto-run commands (`auto_run: true`) are included.
"""

from __future__ import annotations

import json

from . import catalog as catmod
from . import evidence as evmod

PER_FILE = 6000
TOTAL = 60000
TEXT_SUFFIXES = (".txt", ".json", ".xml", ".html", ".htm", ".csv", ".md", ".log", ".js", ".tsv", ".yaml")


HAR_LINES = 400


def har_summary(path, budget: list[int]) -> list[str]:
    """One line per distinct request: method, URL with parameter names only, status,
    response type, request cookie names, and Set-Cookie names with their flags.
    No header, cookie, parameter, or body values (they hold credentials)."""
    try:
        entries = json.loads(path.read_text(errors="replace"))["log"]["entries"]
    except (OSError, ValueError, KeyError, TypeError):
        return ["(not a readable HAR file)"]
    seen, out = set(), []
    for e in entries:
        try:
            req, res = e.get("request") or {}, e.get("response") or {}
            url = str(req.get("url", ""))
            base, _, query = url.partition("?")
            names = [p.split("=", 1)[0] for p in query.split("&") if p] if query else []
            line = f"{req.get('method', '?')} {base}" + (f"?{'&'.join(n + '=…' for n in names)}" if names else "")
            line += f" -> {res.get('status', '?')} {(res.get('content') or {}).get('mimeType', '') or ''}".rstrip()
            post = req.get("postData") or {}
            if post:
                pn = [p.get("name", "") for p in post.get("params") or []]
                if not pn and "json" in (post.get("mimeType") or ""):
                    try:
                        body = json.loads(post.get("text") or "")
                        pn = sorted(body) if isinstance(body, dict) else []
                    except ValueError:
                        pass
                line += f" | body {post.get('mimeType', '')} fields: {', '.join(pn) or '-'}"
            ck = [c.get("name", "") for c in req.get("cookies") or []]
            if ck:
                line += f" | cookies: {', '.join(ck)}"
            sc = []
            for h in res.get("headers") or []:
                if str(h.get("name", "")).lower() == "set-cookie":
                    parts = [x.strip() for x in str(h.get("value", "")).split(";")]
                    flags = [x for x in parts[1:] if x.split("=")[0].lower() in ("secure", "httponly", "samesite", "path", "domain")]
                    sc.append(parts[0].split("=", 1)[0] + (f" ({'; '.join(flags)})" if flags else " (no flags)"))
            if sc:
                line += f" | set-cookie: {', '.join(sc)}"
        except AttributeError:
            continue
        if line in seen:
            continue
        seen.add(line)
        if len(out) >= HAR_LINES or budget[0] <= 0:
            out.append(f"[... more requests not included]")
            break
        budget[0] -= len(line)
        out.append(line)
    return out or ["(no requests)"]


def _excerpt(version: evmod.Version, budget: list[int]) -> list[str]:
    out = []
    for it in version.items:
        label = it.caption or it.name or it.file
        if it.type == "image":
            out.append(f"   - screenshot: {label} (not included; attach the image if needed)")
            continue
        if it.file.lower().endswith(".har"):
            out.append(f"   - HAR file {it.name or it.file}: summary without values (cookies, tokens,"
                       " and parameter values removed):")
            out += ["     " + ln for ln in har_summary(version.path / it.file, budget)]
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
          store: evmod.Store, findings: list[dict], kinds: list | None = None,
          all_tests: bool = False) -> str:
    """`findings`: existing findings to show (this test's, or with all_tests the
    whole target's, for an AI agent). `kinds`: the scenario's finding kinds."""
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
        auto = s.get("auto")
        if auto is not None:
            if auto.status == "missing":
                lines.append(f"   Command output: {auto.note}")
            elif ".har" in s["step"].command:
                lines.append("   Command output: not included (it reads HAR files, which hold cookies and tokens;"
                             " see the HAR summary below)")
            elif budget[0] > 0:
                cut = min(PER_FILE, budget[0])
                text = auto.output or "(no output)"
                budget[0] -= min(len(text), cut)
                more = f"\n     [... {len(text) - cut} more characters not included]" if len(text) > cut else ""
                lines.append(f"   Command output (run by the tool {auto.ran_at}, exit {auto.exit_code}"
                             f"{'; ' + auto.note if auto.note else ''}):")
                lines.append("\n".join("     " + ln for ln in text[:cut].splitlines()) + more)
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
    where = "on this target (all tests)" if all_tests else "for this test"
    if findings:
        lines += ["", f"Findings already recorded {where}:"]
        for f in findings:
            sc = f"{f['cvss']['score']} {f['cvss']['severity']} {f['cvss_vector']}" if f["cvss"] else "not rated"
            key = f" kind={f['kind']} subject={f['subject']!r}" if f.get("kind") else ""
            lines.append(f"- #{f['id']} [{f['test_id']}] {f['title']} [{f['status']}] {sc}{key}")
    else:
        lines += ["", f"Findings already recorded {where}: none"]
    if kinds:
        lines += ["", "Finding kinds for this test (use one per finding, or \"other\"; write the subject exactly",
                  "as described, so the same problem always gets the same kind and subject):"]
        lines += [f"- {k.id}: {k.title}. Subject: {k.subject}" for k in kinds]
    lines += ["", "Answer with: a verdict per step, an overall verdict, and for each fail the observed problem,",
              "its impact, reproduction steps, and a CVSS 3.1 vector with a short rationale per metric.",
              "",
              "End the answer with this JSON block, filled in (it is imported back into the test tool).",
              "One entry per step. verdict is \"pass\", \"fail\", or \"-\" when the evidence is missing, failed,",
              "or not enough to decide. reason: one or two sentences citing the evidence.",
              "findings: one entry per distinct problem (empty list when there is none). kind and subject:",
              "from the finding kinds above. same_as: the number (#id) of a finding already recorded above",
              "that describes the same problem, even with other words or from another test; such an entry",
              "is not created again. Otherwise null. steps: the step numbers that show it. cvss_vector: a full",
              "CVSS 3.1 vector (CVSS:3.1/AV:../AC:../PR:../UI:../S:../C:../I:../A:..); cvss_rationale: one",
              "line per metric. reproduction: exact commands or operations, citing the evidence.",
              "```json",
              json.dumps({"wstg_review": {
                  "test": test.id, "target": target.name, "overall": "pass | fail | -",
                  "summary": "one paragraph",
                  "steps": [{"step": s["n"], "verdict": "pass | fail | -", "reason": "..."} for s in steps],
                  "findings": [{"title": "...", "kind": (kinds[0].id if kinds else "other"),
                                "subject": "...", "same_as": None, "steps": [1], "summary": "...", "impact": "...",
                                "reproduction": "...", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                "cvss_rationale": "..."}]}},
                  indent=2),
              "```"]
    return "\n".join(lines) + "\n"
