"""Malformed-input error probes with the captured session (WSTG-SESS-04, ERRH-01/02).

`wstg-sess --errors --har DIR --base URL [--max N] [--pause S]`

Replays requests from the logged-in `har-browse` capture with deliberately malformed
input, carrying the captured session, and checks each error response for the session
token (or bearer token) echoed back, and for stack traces / debug output that reveal
internal variables. Probes per request template:

- GET with a query: a scalar parameter sent as an array (`name[]=`, invalid type), all
  parameters dropped (missing id), an oversized value, and an invalid percent-encoding;
- a request with a JSON body: the same method with a broken JSON body (it cannot be
  parsed, so it cannot change state);
- once per run: a missing path with an invalid encoding.

Only the host of `--base` is contacted. Requests that look state-changing (logout,
delete, ...) and login requests (lockout counters) are skipped. Token values are masked
in the output, so they stay in the HAR evidence only. Exit 3 when there is no logged-in
HAR, 4 when no probe got an answer.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from . import entrypoints as ep
from . import har as harmod

DEFAULT_MAX = 20
OVERSIZE = 4096
STATIC_RE = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|mp4|webm|pdf)$", re.I)
# Headers of the captured request worth keeping: auth and anti-CSRF headers an API needs.
KEEP_HEADER_RE = re.compile(r"^(authorization|x-csrf-token|x-xsrf-token|x-csrftoken|x-requested-with|"
                            r"x-api-key|accept)$", re.I)

# (label, pattern) of stack traces and debug output that reveal internal state.
DEBUG_PATTERNS = [
    ("python traceback", r"Traceback \(most recent call last\)"),
    ("werkzeug / django debug", r"Werkzeug Debugger|You're seeing this error because you have DEBUG = True"),
    ("java stack trace", r"\bat [a-z][\w$]*(\.[\w$]+)+\([\w$]+\.java:\d+\)|java\.lang\.\w+(Exception|Error)"),
    (".net error page", r"Server Error in '.*' Application|System\.\w+Exception|Stack Trace:</b>"),
    ("php error", r"<b>(Fatal error|Warning|Notice|Parse error)</b>:|\bon line <b>\d+</b>|PHP (Fatal|Warning|Notice)"),
    ("laravel / symfony debug", r"Whoops, looks like something went wrong|Symfony\\Component\\|vendor/laravel/"),
    ("node / express trace", r"\bat [\w.<>]+ \((/|[A-Z]:\\)[^)]+:\d+:\d+\)|node_modules/"),
    ("ruby / rails trace", r"ActionController::|\.rb:\d+:in `"),
    ("sql error", r"SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|PG::\w+Error|sqlite3\.\w*Error"),
    ("server variables", r"HTTP_COOKIE|\$_SESSION|\$_SERVER\[|SESSION_ID\s*[=:]|REMOTE_ADDR\s*[=:]"),
]
_DEBUG_RES = [(label, re.compile(p)) for label, p in DEBUG_PATTERNS]


def _states(folder: Path | None) -> dict[str, dict]:
    out = {}
    for f in ep._files(folder):
        name = re.sub(r"^\d{3}-", "", f.name)
        if name.startswith("storage-state") and f.suffix.lower() == ".json":
            role = ep._STAMP_RE.sub("", name[len("storage-state"):-5].lstrip("-_")) or "session"
            try:
                out[role] = json.loads(f.read_text(errors="replace"))
            except (OSError, ValueError):
                pass
    return out


def logged_in_hars(folder: Path | None) -> list[tuple[str, list]]:
    """[(role, entries)] of the HAR files of logged-in roles (not anon/guest)."""
    out = []
    for f in ep._files(folder):
        if f.suffix.lower() != ".har":
            continue
        role = harmod._role(f.name)
        if harmod._ANON_ROLE_RE.match(role):
            continue
        out.append((role, harmod._load(f) or []))
    return out


def _last_cookie(entries: list, host: str) -> str:
    """Cookie header of the last request to `host` that carried one (the logged-in state)."""
    for e in reversed(entries):
        req = e.get("request") or {}
        if (urlsplit(str(req.get("url", ""))).hostname or "").lower() != host:
            continue
        ck = harmod._header(req.get("headers"), "cookie")
        if not ck:
            ck = "; ".join(f"{c.get('name')}={c.get('value')}" for c in req.get("cookies") or [] if c.get("name"))
        if ck:
            return ck
    return ""


def secrets(entries: list, cookie: str) -> set:
    """Session/auth cookie values and bearer tokens to search for in error bodies."""
    vals = set(harmod._session_values(entries))
    for part in cookie.split(";"):
        n, _, v = part.strip().partition("=")
        if v and len(v) >= 6 and harmod._is_session_cookie(n, set()):
            vals.add(v)
    for e in entries:
        auth = harmod._header((e.get("request") or {}).get("headers"), "authorization")
        tok = auth.split(None, 1)[1].strip() if " " in auth else ""
        if len(tok) >= 12:
            vals.add(tok)
    return vals


def _json_body(req: dict) -> bool:
    post = req.get("postData") or {}
    mime = str(post.get("mimeType") or "").lower()
    text = str(post.get("text") or "").lstrip()
    return "json" in mime or (bool(text) and text[:1] in ("{", "["))


def targets(entries: list, host: str, limit: int) -> tuple[list[dict], list[str]]:
    """Request templates to probe (deduplicated by method and path template), and notes on
    what was skipped."""
    seen, out, skipped = set(), [], []
    for e in entries:
        req = e.get("request") or {}
        url = str(req.get("url", ""))
        sp = urlsplit(url)
        if (sp.hostname or "").lower() != host or STATIC_RE.search(sp.path):
            continue
        method = str(req.get("method", "GET")).upper()
        query = parse_qsl(sp.query, keep_blank_values=True)
        is_json = method in ("POST", "PUT", "PATCH") and _json_body(req)
        if not ((method == "GET" and query) or is_json):
            continue
        key = (method, harmod._template(sp.path))
        if key in seen:
            continue
        seen.add(key)
        label = f"{method} {key[1]}"
        if ep.STATE_PATH_RE.search(sp.path) or ep.LOGIN_URL_RE.search(sp.path):
            skipped.append(f"{label} (looks state-changing or a login; not probed)")
            continue
        if len(out) >= limit:
            skipped.append(f"{label} (over the limit of {limit})")
            continue
        headers = {h.get("name"): h.get("value") for h in req.get("headers") or []
                   if KEEP_HEADER_RE.match(str(h.get("name", "")))}
        out.append({"label": label, "method": method, "path": sp.path or "/", "query": query,
                    "json": is_json, "headers": headers})
    return out, skipped


def probes(t: dict) -> list[tuple[str, str, str, bytes | None, dict]]:
    """[(probe name, method, path+query, body, extra headers)] for one request template."""
    path, q, h = quote(t["path"], safe="/%:@!$&'()*+,;=-._~"), t["query"], dict(t["headers"])
    if t["json"]:
        return [("broken JSON", t["method"], path, b'{"wstg_probe": ',
                 {**h, "Content-Type": "application/json"})]
    first = q[0][0]
    array = [(f"{n}[]" if i == 0 else n, v) for i, (n, v) in enumerate(q)]
    big = [(n, "A" * OVERSIZE if i == 0 else v) for i, (n, v) in enumerate(q)]
    rest = urlencode(q[1:])
    return [
        (f"invalid type ({first}[] array)", "GET", f"{path}?{urlencode(array)}", None, h),
        ("missing parameters", "GET", path, None, h),
        (f"oversized value ({first}, {OVERSIZE} chars)", "GET", f"{path}?{urlencode(big)}", None, h),
        (f"invalid encoding ({first}=%ff%00)", "GET",
         f"{path}?{quote(first)}=%ff%00" + (f"&{rest}" if rest else ""), None, h),
    ]


def inspect(body: str, headers_text: str, values: set) -> list[str]:
    """Problems in one error response: an echoed token (masked) and debug-output labels."""
    hits = []
    echoed = [v for v in values if v in body or v in headers_text]
    if echoed:
        hits.append(f"ERROR-ECHO the session token is echoed back  <= {harmod._mask(echoed[0])}")
    for label, rx in _DEBUG_RES:
        m = rx.search(body)
        if m:
            snippet = re.sub(r"\s+", " ", body[max(0, m.start() - 40):m.end() + 60]).strip()
            for v in values:
                snippet = snippet.replace(v, harmod._mask(v))
            hits.append(f"DEBUG-OUTPUT {label}: …{snippet[:160]}…")
    return hits


def run(args) -> int:
    base = args.base.rstrip("/")
    sp = urlsplit(base)
    host = (sp.hostname or "").lower()
    origin = f"{sp.scheme}://{sp.netloc}"
    folder = Path(args.har) if args.har else None
    hars = logged_in_hars(folder)
    states = _states(folder)
    print(f"# malformed-input error probes against {host} with the captured session "
          "(token values masked; only this host contacted)")
    if not hars:
        print("no logged-in HAR found; capture one with "
              f"`wstg capture {host} --role user` (log in during the walk)", file=sys.stderr)
        return 3
    sent = answered = 0
    bad: list[str] = []
    site_probe_done = False
    for role, entries in hars:
        st = states.get(role)
        cookie = ep.cookie_header(st, sp.scheme, host, "/") if st else ""
        cookie = cookie or _last_cookie(entries, host)
        values = secrets(entries, cookie)
        tlist, skipped = targets(entries, host, args.max)
        print(f"\n== role '{role}': {len(tlist)} request template(s) probed, {len(values)} token value(s) "
              f"tracked, session cookie {'from the storage state' if st and cookie else 'from the HAR' if cookie else 'NONE (probes run without a session)'}")
        for s in skipped:
            print(f"   skipped: {s}")
        plan = [(t["label"], p) for t in tlist for p in probes(t)]
        if not site_probe_done:
            plan.append(("(site)", ("missing path, invalid encoding", "GET", "/wstg-missing-probe/%ff%00", None, {})))
            site_probe_done = True
        for label, (name, method, target, body, headers) in plan:
            if sent and args.pause:
                time.sleep(args.pause)
            a = ep.fetch(origin + target, cookie, {"User-Agent": "wstg-error-probe", **headers}, body, method)
            sent += 1
            if a.status is None:
                print(f"   {label} | {name}: no answer ({a.error})")
                continue
            answered += 1
            hits = inspect(a.body, a.location, values)
            mark = "  [FAIL]" if hits else ""
            print(f"   {label} | {name}: HTTP {a.status} {a.ctype or '-'} {a.size} bytes{mark}")
            if a.status in (301, 302, 303, 307, 308) and ep.LOGIN_URL_RE.search(a.location or ""):
                print("      (sent to login: the captured session may have expired; capture again)")
            for h in hits:
                print(f"      {h}")
                bad.append(f"{label} | {name}: {h.split(' ', 1)[0]}")
    if sent and not answered:
        print(f"no probe to {host} got an answer; collect again", file=sys.stderr)
        return 4
    print()
    if bad:
        print(f"# verdict: FAIL ({len(bad)} error response(s) echo the token or show debug output)")
        for b in bad:
            print(f"   {b}")
    else:
        print(f"# verdict: no token echo or debug output in {answered} malformed-input error response(s)")
    return 0
