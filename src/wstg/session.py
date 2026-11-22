"""Session-fixation analysis (WSTG-SESS-03).

From cookie snapshots taken before and after a manual login (captured in a headful
browser, like `wstg capture`), decide whether the session identifier is reissued at
login, whether a value injected before login survived, and - with one replay - whether
the pre-login identifier is still accepted afterwards. The browser driving and the
replay request live in `capture.py`; the functions here are pure and testable.

Identifier values are masked in the summary (first and last few characters only), so the
result can be judged without the raw identifiers leaving the evidence.
"""
from __future__ import annotations

import re

SESSION_NAME_RE = re.compile(
    r"(phpsessid|jsessionid|asp\.?net_sessionid|cfid|cftoken|_session\b|^session$|session[_-]?id|"
    r"^sessionid$|^sid$|^sess$|connect\.sid|wordpress_logged_in|laravel_session|symfony)", re.I)

SESSION_IN_URL_RE = re.compile(
    r"(;jsessionid=|[?&](jsessionid|phpsessid|sid|sessionid|session|session_id|token)=)", re.I)

LOGIN_FORM_RE = re.compile(r"type=[\"']?password|name=[\"']?(pass|passwd|password|pwd)\b", re.I)


def is_session_cookie(c: dict) -> bool:
    """A cookie that looks like a session identifier: a known name, or HttpOnly."""
    return bool(SESSION_NAME_RE.search(c.get("name", "")) or c.get("httpOnly"))


def session_values(cookies: list[dict]) -> dict[str, str]:
    """{name: value} of the cookies that look like a session identifier."""
    return {c["name"]: c.get("value", "") for c in cookies if c.get("name") and is_session_cookie(c)}


def mask(value: str) -> str:
    v = value or ""
    if len(v) <= 8:
        return "*" * len(v) or "(empty)"
    return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"


def reissue_rows(before: dict, after: dict, injected: dict | None = None) -> list[dict]:
    """One row per session cookie name seen before or after login: whether it was
    reissued and whether an injected value survived login."""
    injected = injected or {}
    rows = []
    for name in sorted(set(before) | set(after)):
        b, a = before.get(name), after.get(name)
        if b is None:
            state, reissued = "issued at login (none before)", True
        elif a is None:
            state, reissued = "cleared after login", True
        elif a == b:
            state, reissued = "NOT REISSUED (same value before and after login)", False
        else:
            state, reissued = "reissued at login", True
        survived = name in injected and a is not None and a == injected[name]
        rows.append({"name": name, "before": b, "after": a, "reissued": reissued,
                     "injected_survived": survived, "state": state})
    return rows


def id_in_urls(urls, values) -> list[str]:
    """URLs that carry a session identifier in the path or query (URL-based fixation)."""
    vals = {v for v in (values or ()) if v and len(v) >= 8}
    hits = [u for u in urls if SESSION_IN_URL_RE.search(u) or any(v in u for v in vals)]
    return sorted(set(hits))


def looks_logged_out(status, location: str, body: str) -> bool:
    """A response that asks the client to authenticate again (so the replayed identifier
    was rejected): 401, a redirect to a login page, or a password form in the body."""
    if status == 401:
        return True
    if status in (301, 302, 303, 307, 308) and re.search(r"login|signin|auth|session", location or "", re.I):
        return True
    return bool(LOGIN_FORM_RE.search(body or ""))
