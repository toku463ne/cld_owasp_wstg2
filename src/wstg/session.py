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


# ---- reading a login from a captured HAR ----------------------------------

PASSWORD_FIELD_RE = re.compile(r"(pass|passwd|password|passwort|pwd|mot_de_passe)", re.I)


def _req_cookies(entry: dict) -> dict[str, str]:
    return {c.get("name", ""): c.get("value", "")
            for c in (entry.get("request") or {}).get("cookies") or [] if c.get("name")}


def _set_cookie_values(entry: dict) -> dict[str, str]:
    out = {}
    for h in (entry.get("response") or {}).get("headers") or []:
        if str(h.get("name", "")).lower() == "set-cookie":
            first = str(h.get("value", "")).split(";", 1)[0]
            if "=" in first:
                n, v = first.split("=", 1)
                out[n.strip()] = v.strip()
    return out


def cookie_header(entry: dict) -> str:
    return "; ".join(f"{n}={v}" for n, v in _req_cookies(entry).items())


def find_login(entries: list, field_names) -> int | None:
    """Index of the first POST whose body carries a password field (the login request)."""
    for i, e in enumerate(entries):
        req = e.get("request") or {}
        if str(req.get("method", "")).upper() == "POST" and any(PASSWORD_FIELD_RE.search(n) for n in field_names(req)):
            return i
    return None


def analyze_har(entries: list, field_names, base_host: str) -> dict:
    """From the entries of one HAR that spans a login, return the session identifier
    before and after login, an authenticated URL on `base_host` to replay against, and the
    request URLs. `field_names(req)` returns a request's body field names."""
    i = find_login(entries, field_names)
    if i is None:
        return {"login_found": False, "urls": [(e.get("request") or {}).get("url", "") for e in entries]}
    login = entries[i]
    sess = lambda d: {n: v for n, v in d.items() if is_session_cookie({"name": n})}  # noqa: E731
    before = sess(_req_cookies(login))
    after = sess(_set_cookie_values(login))
    for e in entries[i + 1:]:                      # fill from later requests when the login response set nothing
        for n, v in sess(_req_cookies(e)).items():
            after.setdefault(n, v)
    authed_url = ""
    for e in entries[i + 1:]:
        req = e.get("request") or {}
        u = req.get("url", "")
        if str(req.get("method", "")).upper() == "GET" and _host(u) == base_host \
                and (e.get("response") or {}).get("status") == 200:
            authed_url = u
            break
    post_entry = next((e for e in entries[i + 1:] if _host((e.get("request") or {}).get("url", "")) == base_host), None)
    return {"login_found": True, "before": before, "after": after, "authed_url": authed_url,
            "pre_cookie": cookie_header(login), "post_cookie": cookie_header(post_entry) if post_entry else "",
            "urls": [(e.get("request") or {}).get("url", "") for e in entries]}


def _host(url: str) -> str:
    from urllib.parse import urlsplit
    return (urlsplit(url).hostname or "").lower()
