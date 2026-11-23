"""Judge ffuf JSON output (WSTG-CONF-04 / CONF-05): real hits vs catch-all answers.

`wstg-ffuf [--backup] [--baseline HTTP404_DIR] FILE`

ffuf's -ac (auto-calibration) drops answers that look like the default "not
found" response, but some sites still answer hundreds of names with one generic
page: a soft 404 with status 200, a redirect of everything to the login page, a
SPA shell, or a proxy / WAF block page. This reads the ffuf JSON (no request is
sent) and splits the results:

- Response groups: results with the same status, word count, line count, content
  type, and redirect target (the fuzzed word in a redirect is written FUZZ, so
  "/a -> /a/" and "/b -> /b/" are one group). A group that holds at least
  max(10, 5%) of the results is a catch-all and is left out (with examples).
- Same as the default 404: with --baseline (the http-404 evidence folder: its
  stdout.txt starts with the status line, body.html is the body), results with
  that status and a size within 2% of the 404 body are left out.
- --backup (backup-ffuf, names tried with .bak, .old, .orig, .zip, .tar.gz, ~):
  a backup name that answers exactly like its base name (`a.bak` like `a`) means
  the server ignores the extension: left out. An archive (.zip, .tar.gz)
  answered with an HTML page is left out as well.

What is left is printed as candidates, tagged STRONG (status 200 and, for a
backup name, a non-HTML content type) or CHECK (anything else: look at it by
hand). The last line is the verdict:

    verdict: CANDIDATES n (STRONG k)  - check these by hand
    verdict: NO-CANDIDATE             - every answer was a catch-all or a 404 look-alike
    verdict: NO-RESULT                - ffuf found nothing at all

When the JSON is missing (ffuf writes it only at the end: the run was stopped
or timed out), the names ffuf printed to stdout.txt next to it (-s mode) are
listed instead, marked PARTIAL, and the exit code is 3 (input missing). Exit 0
otherwise.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

BACKUP_EXTS = (".tar.gz", ".bak", ".old", ".orig", ".zip", "~")
ARCHIVE_EXTS = (".zip", ".tar.gz")
SHOW = 200          # candidates printed at most


@dataclass
class Hit:
    word: str
    url: str
    status: int
    length: int
    words: int
    lines: int
    ctype: str
    redirect: str

    @property
    def group(self) -> tuple:
        return (self.status, self.words, self.lines, self.ctype, self.redirect)

    @property
    def html(self) -> bool:
        return "html" in self.ctype


def _redirect(loc: str, word: str) -> str:
    """Redirect target with the fuzzed word written FUZZ (and the query dropped)."""
    loc = (loc or "").split("?", 1)[0]
    if word and word in loc:
        loc = loc.replace(word, "FUZZ")
    return re.sub(r"^https?://[^/]+", "", loc)


def parse(data: dict) -> list[Hit]:
    hits = []
    for r in data.get("results") or []:
        inp = r.get("input") or {}
        word = str(inp.get("FUZZ", "")) if isinstance(inp, dict) else ""
        url = str(r.get("url", ""))
        if not word:
            word = url.rsplit("/", 1)[-1]
        hits.append(Hit(word=word, url=url, status=int(r.get("status") or 0),
                        length=int(r.get("length") or 0), words=int(r.get("words") or 0),
                        lines=int(r.get("lines") or 0),
                        ctype=str(r.get("content-type") or "").split(";")[0].strip().lower(),
                        redirect=_redirect(str(r.get("redirectlocation") or ""), word)))
    return hits


def backup_base(word: str) -> tuple[str, str] | None:
    """('index.php', '.bak') for 'index.php.bak'; None when no backup extension."""
    for ext in BACKUP_EXTS:
        if word.endswith(ext) and len(word) > len(ext):
            return word[: -len(ext)], ext
    return None


def read_baseline(folder: Path) -> tuple[int, int] | None:
    """(status, body size) of the http-404 evidence, or None."""
    try:
        first = (folder / "stdout.txt").read_text(errors="replace").splitlines()[0]
        status = int(first.split()[1])
        return status, (folder / "body.html").stat().st_size
    except (OSError, IndexError, ValueError):
        return None


def judge(hits: list[Hit], *, backup: bool = False, baseline: tuple[int, int] | None = None):
    """Return (catch-all groups, left-out reasons, candidates)."""
    sizes = Counter(h.group for h in hits)
    limit = max(10, len(hits) * 5 // 100)
    catch_all = {g: n for g, n in sizes.items() if n >= limit}
    by_word = {h.word: h for h in hits}
    out: dict[str, list[Hit]] = defaultdict(list)
    cands: list[tuple[str, Hit]] = []
    for h in hits:
        if h.group in catch_all:
            out["catch-all response"].append(h)
            continue
        if baseline and h.status == baseline[0] and abs(h.length - baseline[1]) <= max(16, baseline[1] // 50):
            out["same as the default 404 page"].append(h)
            continue
        bb = backup_base(h.word) if backup else None
        if bb:
            base = by_word.get(bb[0])
            if base and base.group == h.group:
                out["answers like its base name (extension ignored)"].append(h)
                continue
            if bb[1] in ARCHIVE_EXTS and h.html:
                out["archive name answered with an HTML page"].append(h)
                continue
        strong = h.status == 200 and (not bb or not h.html) and (not backup or bool(bb))
        cands.append(("STRONG" if strong else "CHECK", h))
    cands.sort(key=lambda c: (c[0] != "STRONG", c[1].status, c[1].url))
    return catch_all, out, cands


def _group_text(g: tuple) -> str:
    status, words, lines, ctype, redirect = g
    s = f"{status} words={words} lines={lines} type={ctype or '-'}"
    return s + (f" -> {redirect}" if redirect else "")


def report(path: Path, *, backup: bool, baseline_dir: Path | None) -> int:
    name = "backup-ffuf" if backup else "ffuf"
    print(f"# {name} results from {path.name} (no request sent)")
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError) as e:
        return partial(path, e)
    hits = parse(data)
    baseline = read_baseline(baseline_dir) if baseline_dir else None
    if baseline_dir:
        print(f"default 404: " + (f"status {baseline[0]}, {baseline[1]} bytes" if baseline
                                   else "not readable (http-404 not collected?): 404 look-alikes are not left out"))
    print(f"results: {len(hits)}  status: " +
          (", ".join(f"{s}x{n}" for s, n in sorted(Counter(h.status for h in hits).items())) or "-"))
    if not hits:
        print("verdict: NO-RESULT (ffuf found no name that differs from the calibrated not-found answer)")
        return 0
    catch_all, out, cands = judge(hits, backup=backup, baseline=baseline)
    print("\n## Largest response groups (status, words, lines, type, redirect)")
    for g, n in Counter(h.group for h in hits).most_common(8):
        ex = [h.word for h in hits if h.group == g][:5]
        mark = "  CATCH-ALL" if g in catch_all else ""
        print(f"{n:6}  {_group_text(g)}{mark}  e.g. {', '.join(ex)}")
    if out:
        print("\n## Left out")
        for why, hs in out.items():
            print(f"{len(hs):6}  {why}  e.g. {', '.join(h.word for h in hs[:5])}")
    print("\n## Candidates (check by hand)")
    if not cands:
        print("none")
    for tag, h in cands[:SHOW]:
        extra = f" -> {h.redirect}" if h.redirect else ""
        print(f"{tag:6}  {h.status}  {h.length:>8}  {h.ctype or '-':<24}  {h.url}{extra}")
    if len(cands) > SHOW:
        print(f"... {len(cands) - SHOW} more (jq -r '.results[] | [.status, .length, .url] | @tsv' {path})")
    strong = sum(1 for t, _ in cands if t == "STRONG")
    if catch_all and len(hits) - sum(catch_all.values()) < len(hits) // 10:
        print(f"note: {sum(catch_all.values())} of {len(hits)} answers are a catch-all; -ac did not filter it. "
              "Rerun with -fw/-fl of that group or accept the candidates above as the real list.")
    print(f"verdict: CANDIDATES {len(cands)} (STRONG {strong})" if cands else
          "verdict: NO-CANDIDATE (every answer was a catch-all or looked like the 404 page)")
    return 0


def partial(path: Path, err: Exception) -> int:
    print(f"input missing: {path.name} not readable ({err.__class__.__name__}); "
          "ffuf writes it only when it finishes (stopped or timed out?)")
    out = path.parent / "stdout.txt"
    try:
        names = [ln.strip() for ln in out.read_text(errors="replace").splitlines() if ln.strip()]
    except OSError:
        names = []
    if names:
        print(f"PARTIAL: stdout.txt lists {len(names)} names ffuf reported before it stopped "
              "(no status or size; many short common words usually mean a catch-all answer):")
        for n in names[:SHOW]:
            print(f"  {n}")
        if len(names) > SHOW:
            print(f"  ... {len(names) - SHOW} more")
    print("verdict: INCOMPLETE (collect again; the JSON is needed to judge)")
    return 3


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-ffuf", description=__doc__.split("\n\n")[0])
    ap.add_argument("file", type=Path, help="ffuf JSON output (-of json)")
    ap.add_argument("--backup", action="store_true", help="names were tried with backup extensions (backup-ffuf)")
    ap.add_argument("--baseline", type=Path, help="http-404 evidence folder (stdout.txt, body.html)")
    args = ap.parse_args(argv)
    return report(args.file, backup=args.backup, baseline_dir=args.baseline)


if __name__ == "__main__":
    raise SystemExit(main())
