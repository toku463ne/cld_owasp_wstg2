"""Session-fixation check from a captured login HAR (WSTG-SESS-03).

`wstg-sess --har DIR --base URL [--pause S]`

Reuses the `har-browse` capture the tester already records (one HAR that spans a login:
anonymous, then logged in). From it the tool reads the session identifier before and after
login and decides whether it is reissued, scans the request URLs for a session id in a URL
(URL-based fixation), and - best effort - replays the pre-login cookie against an
authenticated URL seen in the HAR to check whether the old identifier is still accepted.

Only the host of `--base` is contacted (the one replay request); GET only; identifier
values are masked in the output, so the raw identifiers stay in the HAR evidence only.
Exit 3 when no HAR with a login was found.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import entrypoints as ep
from . import har as harmod
from . import session as se


def _login_har(folder: Path, base_host: str) -> tuple[str, dict] | None:
    """The first HAR file in the folder that spans a login, with its analysis."""
    for f in ep._files(folder):
        if f.suffix.lower() != ".har":
            continue
        entries = harmod._load(f) or []
        res = se.analyze_har(entries, harmod._body_field_names, base_host)
        if res.get("login_found"):
            return harmod._role(f.name), res
    return None


def _replay(base: str, res: dict) -> dict:
    authed, pre, post = res.get("authed_url", ""), res.get("pre_cookie", ""), res.get("post_cookie", "")
    base_host = (urlsplit(base).hostname or "").lower()
    if not authed or (urlsplit(authed).hostname or "").lower() != base_host:
        return {"verdict": "not tested", "detail": "no in-scope authenticated URL in the HAR to replay against"}
    if not pre or pre == post:
        return {"verdict": "not tested", "detail": "no distinct pre-login cookie to replay"}
    a_post, a_pre = ep.fetch(authed, post), ep.fetch(authed, pre)
    if a_pre.status is None:
        return {"verdict": "not tested", "detail": f"the replay request got no answer ({a_pre.error})"}
    if se.looks_logged_out(a_pre.status, a_pre.location, a_pre.body):
        return {"verdict": "rejected", "detail": f"replayed pre-login cookie -> HTTP {a_pre.status} (login required)"}
    if a_pre.status == 200 and a_post.status == 200:
        return {"verdict": "still accepted",
                "detail": f"replayed pre-login cookie -> HTTP 200 like the logged-in page ({a_pre.size} vs {a_post.size} bytes)"}
    return {"verdict": "inconclusive", "detail": f"pre-login replay HTTP {a_pre.status}, logged-in HTTP {a_post.status}"}


def run(args) -> int:
    base_host = (urlsplit(args.base).hostname or "").lower()
    found = _login_har(Path(args.har) if args.har else None, base_host)
    print(f"# session fixation check of {base_host} from the login HAR (identifier values masked)")
    if not found:
        print("no HAR with a login (a POST carrying a password field) was found; capture a logged-in session "
              f"with `wstg capture {base_host} --role user` that includes the login step", file=sys.stderr)
        return 3
    role, res = found
    before, after = res["before"], res["after"]
    print(f"# login found in the '{role}' HAR")
    rows = se.reissue_rows(before, after)
    url_hits = se.id_in_urls(res["urls"], set(before.values()) | set(after.values()))
    if args.pause:
        time.sleep(args.pause)
    replay = _replay(args.base, res)

    fail = False
    if not rows:
        print("- no session cookie seen before or after login (check the login flow / cookie names)")
    for r in rows:
        tag = "[GOOD]" if r["reissued"] else "[FAIL]"
        fail = fail or not r["reissued"]
        print(f"- {r['name']}: {r['state']} {tag} (before {se.mask(r['before'] or '')}, after {se.mask(r['after'] or '')})")
    print(f"- pre-login identifier still accepted after login: {replay['verdict']} "
          f"{'[FAIL]' if replay['verdict'] == 'still accepted' else '[GOOD]' if replay['verdict'] == 'rejected' else ''}"
          f" ({replay['detail']})")
    fail = fail or replay["verdict"] == "still accepted"
    print(f"- session identifier in a URL or parameter: {'FOUND ' + str(len(url_hits)) + ' [FAIL]' if url_hits else 'none seen'}")
    for h in url_hits[:10]:
        print(f"    {h}")
    print(f"\n# verdict: {'FAIL (session fixation)' if fail else 'no fixation detected from this capture'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-sess", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--har", help="har-browse evidence version folder")
    ap.add_argument("--pause", type=int, default=0)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
