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

import json
import re
from urllib.parse import parse_qsl, urlsplit

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

# Password field names, including common non-English ones (the login form may be localised):
# senha (pt), contrasena/contrasenha (es), mot_de_passe/motdepasse (fr), passwort (de),
# wachtwoord (nl), losenord (sv), salasana (fi), parola (it/tr), lozinka (hr), haslo (pl).
PASSWORD_FIELD_RE = re.compile(
    r"(pass|passwd|password|passwort|pwd|mot[_-]?de[_-]?passe|senha|contrase|wachtwoord|"
    r"l(o|ö)senord|salasana|parol|lozinka|has(l|ł)o|密码|パスワード)", re.I)


def _req_cookies(entry: dict) -> dict[str, str]:
    """{name: value} of the cookies a request sent (the HAR cookie list, else the Cookie header)."""
    req = entry.get("request") or {}
    out = {c.get("name", ""): c.get("value", "") for c in req.get("cookies") or [] if c.get("name")}
    if not out:
        for h in req.get("headers") or []:
            if str(h.get("name", "")).lower() == "cookie":
                for part in str(h.get("value", "")).split(";"):
                    n, sep, v = part.strip().partition("=")
                    if sep and n:
                        out[n] = v
    return out


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


def _json_keys(obj) -> list:
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(k)
            out += _json_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _json_keys(v)
    return out


def login_fields(req: dict) -> list:
    """A request's body field names, read from form params, a JSON body (keys, nested),
    or a urlencoded body text - so a login is found whatever the form submits as."""
    post = req.get("postData") or {}
    names = [p.get("name", "") for p in post.get("params") or []]
    text = (post.get("text") or "").strip()
    mime = (post.get("mimeType") or "").lower()
    if "json" in mime or text.startswith(("{", "[")):
        try:
            names += _json_keys(json.loads(text))
        except ValueError:
            pass
    if not post.get("params") and ("urlencoded" in mime or ("=" in text and "{" not in text)):
        names += [k for k, _ in parse_qsl(text)]
    return [n for n in names if n]


def find_login(entries: list, field_names=login_fields) -> int | None:
    """Index of the first POST whose body carries a password field (the login request)."""
    for i, e in enumerate(entries):
        req = e.get("request") or {}
        if str(req.get("method", "")).upper() == "POST" and any(PASSWORD_FIELD_RE.search(n) for n in field_names(req)):
            return i
    return None


def _sess(d: dict) -> dict:
    return {n: v for n, v in d.items() if is_session_cookie({"name": n})}


def _authed_url(entries: list, base_host: str) -> str:
    for e in entries:
        req = e.get("request") or {}
        u = req.get("url", "")
        if str(req.get("method", "")).upper() == "GET" and _host(u) == base_host \
                and (e.get("response") or {}).get("status") == 200:
            return u
    return ""


def _first_last_session_values(entries: list) -> tuple[dict, dict]:
    """The first and last value seen for each session cookie across the capture (in request
    Cookie headers and response Set-Cookie), in order - a login-language-independent view."""
    first, last = {}, {}
    for e in entries:
        for n, v in _sess(_req_cookies(e)).items():
            first.setdefault(n, v)
            last[n] = v
        for n, v in _sess(_set_cookie_values(e)).items():
            first.setdefault(n, v)
            last[n] = v
    return first, last


def analyze_har(entries: list, field_names=login_fields, base_host: str = "") -> dict:
    """From the entries of one HAR that spans a login, return the session identifier before
    and after login and an authenticated URL on `base_host` to replay against. When the login
    request can be located (a password field in its body) the identifier is read across that
    request; otherwise it falls back to the first/last value of each session cookie in the
    capture (`how` says which). `field_names(req)` returns a request's body field names."""
    urls = [(e.get("request") or {}).get("url", "") for e in entries]
    i = find_login(entries, field_names)
    if i is not None:
        login = entries[i]
        before = _sess(_req_cookies(login))
        after = _sess(_set_cookie_values(login))
        for e in entries[i + 1:]:                  # fill from later requests when the login response set nothing
            for n, v in _sess(_req_cookies(e)).items():
                after.setdefault(n, v)
        for name in before:                        # a reissued name gets its post value from later requests
            if name not in after:
                for e in entries[i + 1:]:
                    rc = _req_cookies(e)
                    if name in rc:
                        after[name] = rc[name]
                        break
        authed_url = _authed_url(entries[i + 1:], base_host)
        how = "login request"
    else:
        before, after = _first_last_session_values(entries)
        authed_url = _authed_url(entries, base_host)
        how = "cookie timeline (login request not auto-detected)"
    return {"login_found": i is not None, "has_session": bool(before or after), "how": how,
            "before": before, "after": after, "authed_url": authed_url, "urls": urls}


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


# ---- logout (WSTG-SESS-06) ------------------------------------------------

# A logout in the URL (path or query), including common non-English words: sair/encerrar
# (pt), salir/desconectar/cerrar sesion (es), deconnexion (fr), abmelden (de), uitloggen (nl).
LOGOUT_PATH_RE = re.compile(
    r"(log[-_]?out|sign[-_]?out|log[-_]?off|sign[-_]?off|end[-_]?session|(?<![a-z])sair(?![a-z])|"
    r"(?<![a-z])salir(?![a-z])|desconectar|cerrar[-_]?sesi|encerrar[-_]?sess|d[eé]connexion|abmelden|"
    r"uitloggen|ログアウト)", re.I)
# Load-balancer, CDN, and analytics cookies: never the session, and their values change often.
NOT_SESSION_RE = re.compile(r"^(awsalb|awsalbcors|awsalbtg|awselb|bigipserver|ts0|__cf|cf_|_cfuvid|arraffinity|"
                            r"_ga|_gid|_gat|_fbp|_hj|nlbi_|incap_|visid_incap|ak_bmsc|bm_)", re.I)
# Cookie names that look like an authentication cookie even without HttpOnly.
AUTH_NAME_RE = re.compile(r"(sess|sid\b|auth|token|login|logged|remember|user|jwt|\.aspx)", re.I)


def session_names(entries: list) -> set:
    """Names of the cookies that look like the session or authentication cookie in this
    HAR: a known session name, an auth-like name, or a cookie set with HttpOnly."""
    out = set()
    for e in entries:
        for n in _req_cookies(e):
            if SESSION_NAME_RE.search(n) or AUTH_NAME_RE.search(n):
                out.add(n)
        for h in (e.get("response") or {}).get("headers") or []:
            if str(h.get("name", "")).lower() != "set-cookie":
                continue
            v = str(h.get("value", ""))
            n = v.split("=", 1)[0].strip()
            if n and (re.search(r";\s*httponly", v, re.I) or SESSION_NAME_RE.search(n) or AUTH_NAME_RE.search(n)):
                out.add(n)
    return {n for n in out if not NOT_SESSION_RE.match(n)}


def _url_text(entry: dict) -> str:
    sp = urlsplit(str((entry.get("request") or {}).get("url", "")))
    return f"{sp.path}?{sp.query}" if sp.query else sp.path


# The dedicated logout capture (`wstg capture <fqdn> --role logout`): its session has
# ended, so the checks that need a live session leave it out.
LOGOUT_ROLE_RE = re.compile(r"^logout\b", re.I)


def cleared_names(entry: dict, names: set | None = None) -> set:
    """Session cookie names the response expires or empties (Max-Age=0, a past Expires,
    or an empty value). `names`: the HAR's session cookie names (session_names)."""
    out = set()
    for h in (entry.get("response") or {}).get("headers") or []:
        if str(h.get("name", "")).lower() != "set-cookie":
            continue
        v = str(h.get("value", ""))
        name, _, rest = v.partition("=")
        name = name.strip()
        if not (name in (names or ()) or is_session_cookie({"name": name})):
            continue
        val = rest.split(";", 1)[0].strip().strip('"')
        if (not val or val.lower() in ("deleted", "null", "none")
                or re.search(r"max-age\s*=\s*(0|-\d+)\b", v, re.I)
                or re.search(r"expires\s*=\s*[^;]*(19[0-9]{2}|200[0-9])", v, re.I)):
            out.add(name)
    return out


def logout_index(entries: list, host: str = "", by_cookie_change: bool = False) -> int | None:
    """Index of the logout request in a HAR: the first request whose URL (path or query)
    looks like a logout, else the first response that clears a session cookie after a
    session was in use. With `by_cookie_change` (the dedicated logout capture) it falls back
    to the last point where the session cookie value sent to `host` stops being sent."""
    return logout_find(entries, host, by_cookie_change)[0]


def logout_find(entries: list, host: str = "", by_cookie_change: bool = False) -> tuple[int | None, str]:
    """(index, how) of the logout; see logout_index."""
    for i, e in enumerate(entries):
        if LOGOUT_PATH_RE.search(_url_text(e)):
            return i, "logout URL"
    names = session_names(entries)
    seen_session = False
    for i, e in enumerate(entries):
        if names & set(_req_cookies(e)):
            seen_session = True
        if seen_session and cleared_names(e, names):
            return i, "response that clears the session cookie"
    if not by_cookie_change:
        return None, ""
    on_host = [(i, e) for i, e in enumerate(entries)
               if not host or _host(str((e.get("request") or {}).get("url", ""))) == host]
    last_change = None
    for k in range(1, len(on_host)):
        (pi, pe), (_, ce) = on_host[k - 1], on_host[k]
        prev, cur = _req_cookies(pe), _req_cookies(ce)
        for n in names & set(prev):
            v = prev[n]
            if cur.get(n) != v and not any(_req_cookies(x).get(n) == v for _, x in on_host[k:]):
                last_change = pi        # the request whose response ended this value
    return (last_change, "session cookie value stops being sent (no logout URL recognised)") \
        if last_change is not None else (None, "")
