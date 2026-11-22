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

`wstg-sess --errors ...` runs the malformed-input error probes instead (see sesserror.py).
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
from . import sesserror


def _best_har(folder: Path, base_host: str) -> tuple[str, dict] | None:
    """The HAR in the folder to analyse: the first that spans a login if any, else the first
    that holds a session cookie (so a non-English login still yields a timeline analysis)."""
    fallback = None
    for f in ep._files(folder):
        if f.suffix.lower() != ".har":
            continue
        entries = harmod._load(f) or []
        res = se.analyze_har(entries, se.login_fields, base_host)
        if res.get("login_found"):
            return harmod._role(f.name), res
        if fallback is None and res.get("has_session"):
            fallback = (harmod._role(f.name), res)
    return fallback


def _cookie_str(values: dict) -> str:
    return "; ".join(f"{n}={v}" for n, v in values.items())


def _replay(base: str, res: dict) -> dict:
    authed = res.get("authed_url", "")
    pre, post = _cookie_str(res.get("before") or {}), _cookie_str(res.get("after") or {})
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
    found = _best_har(Path(args.har) if args.har else None, base_host)
    print(f"# session fixation check of {base_host} from the login HAR (identifier values masked)")
    if not found:
        print("no session cookie was found in any HAR; capture a logged-in session with "
              f"`wstg capture {base_host} --role user` that starts logged out and logs in during the walk",
              file=sys.stderr)
        return 3
    role, res = found
    before, after = res["before"], res["after"]
    login_found = res["login_found"]
    if login_found:
        print(f"# login found in the '{role}' HAR (identifier read across the login request)")
    else:
        print(f"# login request was NOT auto-detected in the '{role}' HAR; comparing the first and last "
              "value of each session cookie instead (verify the login happened during the capture)")
    rows = se.reissue_rows(before, after)
    url_hits = se.id_in_urls(res["urls"], set(before.values()) | set(after.values()))
    if args.pause:
        time.sleep(args.pause)
    replay = _replay(args.base, res)

    fail = False                       # a definite failure (reported as such regardless of login detection)
    if not rows:
        print("- no session cookie seen (check the login flow / cookie names)")
    for r in rows:
        if r["reissued"]:
            tag = "[GOOD]"
        elif login_found:
            tag = "[FAIL]"
            fail = True
        else:
            tag = "[INCONCLUSIVE: could not confirm a reissue without the login request]"
        print(f"- {r['name']}: {r['state']} {tag} (before {se.mask(r['before'] or '')}, after {se.mask(r['after'] or '')})")
    print(f"- pre-login identifier still accepted after login: {replay['verdict']} "
          f"{'[FAIL]' if replay['verdict'] == 'still accepted' else '[GOOD]' if replay['verdict'] == 'rejected' else ''}"
          f" ({replay['detail']})")
    fail = fail or replay["verdict"] == "still accepted"
    print(f"- session identifier in a URL or parameter: {'FOUND ' + str(len(url_hits)) + ' [FAIL]' if url_hits else 'none seen'}")
    for h in url_hits[:10]:
        print(f"    {h}")
    if url_hits:
        fail = True
    if fail:
        verdict = "FAIL (session fixation)"
    elif not login_found and not any(r["reissued"] for r in rows):
        verdict = "INCONCLUSIVE (login not auto-detected; confirm reissue by hand or check the login field name)"
    else:
        verdict = "no fixation detected from this capture"
    print(f"\n# verdict: {verdict}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-sess", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--har", help="har-browse evidence version folder")
    ap.add_argument("--pause", type=int, default=0)
    ap.add_argument("--errors", action="store_true",
                    help="instead: malformed-input error probes with the captured session (WSTG-SESS-04)")
    ap.add_argument("--max", type=int, default=sesserror.DEFAULT_MAX, help="--errors: request templates to probe")
    args = ap.parse_args(argv)
    return sesserror.run(args) if args.errors else run(args)


if __name__ == "__main__":
    raise SystemExit(main())
