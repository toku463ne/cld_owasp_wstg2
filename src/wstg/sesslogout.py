"""Logout invalidation check from a captured logout (WSTG-SESS-06).

`wstg-sess --logout --har DIR --base URL [--pause S]`

Reads a `har-browse` capture that logs in, opens a page, and logs out (record it with
`wstg capture <fqdn> --role logout`). From it the tool finds the logout request, the
session cookie that was in use just before it, whether the logout response clears that
cookie in the browser, and whether the browser still held it afterwards (the storage
state is saved at the end of the capture). Then it replays the pre-logout cookie
against authenticated pages seen before the logout, each compared with the same page
fetched without a cookie, to tell whether the server still accepts the old session.

Only the host of `--base` is contacted; GET only (at most two requests per candidate
page, three candidates); cookie values are masked. Exit 3 when no HAR with a logout and
a session was found.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import entrypoints as ep
from . import har as harmod
from . import session as se

MAX_CANDIDATES = 3


def _find(folder: Path | None) -> tuple[str, list, int] | None:
    """(role, entries, logout index) of the first HAR that logs out after using a session."""
    for f in ep._files(folder):
        if f.suffix.lower() != ".har":
            continue
        entries = harmod._load(f) or []
        i = se.logout_index(entries)
        if i is not None and any(se._sess(se._req_cookies(e)) for e in entries[:i + 1]):
            return harmod._role(f.name), entries, i
    return None


def _state_for(folder: Path | None, role: str) -> dict | None:
    for f in ep._files(folder):
        name = re.sub(r"^\d{3}-", "", f.name)
        if name.startswith("storage-state") and f.suffix.lower() == ".json":
            r = ep._STAMP_RE.sub("", name[len("storage-state"):-5].lstrip("-_")) or "session"
            if r == role:
                try:
                    return json.loads(f.read_text(errors="replace"))
                except (OSError, ValueError):
                    return None
    return None


def pre_logout_session(entries: list, i: int, host: str) -> dict[str, str]:
    """Session cookies sent with the logout request, else with the last request to the
    host before it."""
    sess = se._sess(se._req_cookies(entries[i]))
    if sess:
        return sess
    for e in reversed(entries[:i]):
        if (urlsplit(str((e.get("request") or {}).get("url", ""))).hostname or "").lower() == host:
            sess = se._sess(se._req_cookies(e))
            if sess:
                return sess
    return {}


def candidates(entries: list, i: int, host: str, names: set) -> list[dict]:
    """Authenticated pages before the logout: GET 200 on the host that carried the session
    cookie and are not static, login, or logout pages (latest first)."""
    out, seen = [], set()
    for e in reversed(entries[:i]):
        req, resp = e.get("request") or {}, e.get("response") or {}
        url = str(req.get("url", ""))
        sp = urlsplit(url)
        if (sp.hostname or "").lower() != host or str(req.get("method", "")).upper() != "GET":
            continue
        if resp.get("status") != 200 or harmod._STATIC_RE.search(sp.path):
            continue
        if ep.LOGIN_URL_RE.search(sp.path) or se.LOGOUT_PATH_RE.search(sp.path) or ep.STATE_PATH_RE.search(sp.path):
            continue
        if not names & set(se._req_cookies(e)):
            continue
        key = harmod._template(sp.path)
        if key in seen:
            continue
        seen.add(key)
        size = (resp.get("content") or {}).get("size") or resp.get("bodySize") or 0
        out.append({"url": url, "path": key, "size": int(size) if isinstance(size, (int, float)) else 0})
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def judge(old, anon) -> tuple[str, str]:
    """Verdict for one page: the pre-logout cookie's answer compared with no cookie."""
    if old.status is None:
        return "not tested", f"no answer ({old.error})"
    if se.looks_logged_out(old.status, old.location, old.body):
        return "rejected", f"old cookie -> HTTP {old.status} (login required)"
    if old.status == 200:
        if anon.status == 200 and abs(anon.size - old.size) <= max(64, old.size // 20):
            return "public page", f"HTTP 200 with and without the cookie ({old.size} vs {anon.size} bytes)"
        return "still accepted", (f"old cookie -> HTTP 200 ({old.size} bytes); without a cookie -> "
                                  f"{anon.short()}")
    if old.status in (401, 403):
        return "rejected", f"old cookie -> HTTP {old.status}"
    return "inconclusive", f"old cookie -> {old.short()}; without a cookie -> {anon.short()}"


def run(args) -> int:
    base = args.base.rstrip("/")
    sp = urlsplit(base)
    host = (sp.hostname or "").lower()
    folder = Path(args.har) if args.har else None
    print(f"# logout invalidation check of {host} from the logout capture (cookie values masked)")
    found = _find(folder)
    if not found:
        print("input missing: evidence har-browse has no HAR with a logout after a logged-in session; add one with "
              f"`wstg capture {host} --role logout` (log in, open one page, log out, press Enter), then collect this again",
              file=sys.stderr)
        return 3
    role, entries, i = found
    logout_req = entries[i].get("request") or {}
    lp = urlsplit(str(logout_req.get("url", "")))
    print(f"# logout found in the '{role}' HAR: {str(logout_req.get('method', '?')).upper()} "
          f"{harmod._template(lp.path or '/')}")
    sess = pre_logout_session(entries, i, host)
    if not sess:
        print("- no session cookie was sent before the logout; cannot check (is the login in the capture?)")
        print("\n# verdict: INCONCLUSIVE (no session cookie before the logout)")
        return 0
    names = set(sess)
    print("- session cookie(s) before logout: " + ", ".join(f"{n} {se.mask(v)}" for n, v in sess.items()))

    # Client side: does the logout (or what follows) clear the cookie, and is it kept?
    after = entries[i:i + 6]          # the logout response and the redirects that follow it
    cleared = sorted(names & set().union(*(se.cleared_names(e) for e in after)))
    replaced = [n for n in names if any(se._set_cookie_values(e).get(n) not in (None, sess[n])
                                        for e in after) and n not in cleared]
    print(f"- logout response clears the cookie in the browser: "
          f"{'yes (' + ', '.join(sorted(cleared)) + ')' if cleared else 'replaced with a new value (' + ', '.join(sorted(replaced)) + ')' if replaced else 'NO'}")
    later = [n for n in names if any(se._req_cookies(e).get(n) == sess[n] for e in entries[i + 1:])]
    if later:
        print(f"- the browser still sent the old value after logout: {', '.join(sorted(later))}")
    st = _state_for(folder, role)
    if st is not None:
        kept = [c.get("name") for c in st.get("cookies") or [] if c.get("name") in names
                and c.get("value") == sess.get(c.get("name"))]
        print(f"- old cookie still in the browser at the end of the capture: "
              f"{'YES (' + ', '.join(kept) + ')' if kept else 'no'}")

    # Server side: replay the old cookie.
    cookie = "; ".join(f"{n}={v}" for n, v in sess.items())
    cands = candidates(entries, i, host, names)
    if not cands:
        print("- server-side check: not tested (no authenticated page before the logout in the HAR; "
              "open one page between login and logout)")
        print("\n# verdict: INCONCLUSIVE (no authenticated page to replay)")
        return 0
    origin = f"{sp.scheme}://{sp.netloc}"
    results = []
    sent = 0
    for c in cands:
        u = urlsplit(c["url"])
        target = origin + (u.path or "/") + (f"?{u.query}" if u.query else "")
        if sent and args.pause:
            time.sleep(args.pause)
        old = ep.fetch(target, cookie)
        if args.pause:
            time.sleep(args.pause)
        anon = ep.fetch(target)
        sent += 2
        v, detail = judge(old, anon)
        results.append(v)
        print(f"- replay {c['path']} with the pre-logout cookie: {v}"
              f"{' [FAIL]' if v == 'still accepted' else ' [GOOD]' if v == 'rejected' else ''} ({detail})")
    if "still accepted" in results:
        verdict = "FAIL (the server still accepts the session after logout)"
    elif "rejected" in results:
        verdict = "logout invalidates the session on the server"
        if not cleared and not replaced:
            verdict += " (the cookie is not cleared in the browser; minor)"
    elif all(r == "not tested" for r in results):
        print("no replay got an answer; collect again", file=sys.stderr)
        return 4
    else:
        verdict = "INCONCLUSIVE (the replayed pages look public or answered unclearly; open a page only a logged-in user sees)"
    print(f"\n# verdict: {verdict}")
    return 0
