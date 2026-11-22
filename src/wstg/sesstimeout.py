"""Session timeout measurement from dedicated captures (WSTG-SESS-07).

`wstg-sess --timeout --har DIR --base URL [--idle-steps M,M,...] [--max-minutes N]
[--keepalive M] [--pause S]`

Idle timeout: reads the `timeout` capture in har-timeout (`wstg capture <fqdn> --role
timeout`: log in, open one page only a logged-in user sees, press Enter without logging
out). Every authenticated request resets the server's idle timer, so the tool checks
the session once right away (idle = time since the capture's last request) and then
waits ever longer between checks (5, 10, 15, 20, 30, 45, 60 minutes by default). The
first rejected check bounds the idle timeout: between the previous accepted wait and
this one.

Absolute timeout (optional): with a `timeout-active` capture as well, its session is
kept busy with one request every `--keepalive` minutes (5 by default) until the server
rejects it or `--max-minutes` pass; the lifetime is counted from that capture's login.

Each check is one GET of an authenticated page from the capture, compared with the
same page fetched without a cookie. Only the host of `--base` is contacted; cookie
values are masked. The run takes hours; it ends as soon as both answers are known.
Exit 3 when there is no usable timeout capture.
"""
from __future__ import annotations

import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import entrypoints as ep
from . import har as harmod
from . import session as se
from . import sesslogout as lo

DEFAULT_IDLE_STEPS = (5, 10, 15, 20, 30, 45, 60)
DEFAULT_MAX_MINUTES = 240
DEFAULT_KEEPALIVE = 5
IDLE_LONG = 30           # minutes; above this the idle timeout is flagged LONG (ASVS L2 guidance)
ABSOLUTE_LONG = 12 * 60  # minutes

# Indirection so tests can run the schedule without waiting.
now = time.time
sleep = time.sleep


def _ts(entry: dict) -> float | None:
    v = str(entry.get("startedDateTime") or "")
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def _fmt(minutes: float) -> str:
    return f"{minutes:.0f} min" if minutes < 120 else f"{minutes / 60:.1f} h"


class Session:
    """One captured session: its cookie jar, a page to check, and its times."""

    def __init__(self, role: str, entries: list, host: str, origin: str):
        self.role, self.host, self.origin = role, host, origin
        names = se.session_names(entries)
        on_host = [e for e in entries
                   if (urlsplit(str((e.get("request") or {}).get("url", ""))).hostname or "").lower() == host]
        self.jar = lo.pre_logout_cookies(entries, len(entries) - 1, host) if entries else {}
        self.sess = {n: v for n, v in self.jar.items() if n in names}
        self.cookie = "; ".join(f"{n}={v}" for n, v in self.jar.items())
        self.pages = lo.candidates(entries, len(entries), host, set(self.sess))
        times = [t for t in (_ts(e) for e in on_host) if t]
        self.last_used = max(times) if times else None
        login = se.find_login(entries)
        first_sess = next((e for e in on_host if set(self.sess) & set(se._req_cookies(e))), None)
        self.login_at = _ts(entries[login]) if login is not None else (_ts(first_sess) if first_sess else None)
        self.page = None
        self.expires = _cookie_expiry(entries, set(self.sess))

    def check(self) -> tuple[str, str]:
        """(verdict, detail) of one authenticated request (plus one without a cookie)."""
        u = urlsplit(self.page["url"])
        target = self.origin + (u.path or "/") + (f"?{u.query}" if u.query else "")
        old = ep.fetch(target, self.cookie)
        anon = ep.fetch(target)
        return lo.judge(old, anon)

    def pick_page(self) -> tuple[str, str]:
        """Choose the first candidate page that answers as authenticated now."""
        last = ("not tested", "no authenticated page in the capture")
        for p in self.pages:
            self.page = p
            v, d = self.check()
            if v in ("still accepted", "rejected"):
                return v, d
            last = (v, d)
        self.page = None
        return last


def _cookie_expiry(entries: list, names: set) -> float | None:
    """The latest client-side expiry (Max-Age / Expires) the server set on a session
    cookie, as a timestamp; None for a browser-session cookie."""
    best = None
    for e in entries:
        t0 = _ts(e)
        for h in (e.get("response") or {}).get("headers") or []:
            if str(h.get("name", "")).lower() != "set-cookie":
                continue
            v = str(h.get("value", ""))
            if v.split("=", 1)[0].strip() not in names:
                continue
            m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
            if m and t0:
                exp = t0 + int(m.group(1))
            else:
                m = re.search(r"expires\s*=\s*([^;]+)", v, re.I)
                if not m:
                    continue
                try:
                    from email.utils import parsedate_to_datetime
                    exp = parsedate_to_datetime(m.group(1).strip()).timestamp()
                except (TypeError, ValueError):
                    continue
            best = exp if best is None else max(best, exp)
    return best


def _hars(folder: Path | None, pattern: str) -> tuple[str, list] | None:
    for f in ep._files(folder):
        if f.suffix.lower() == ".har" and re.match(pattern, harmod._role(f.name), re.I):
            return harmod._role(f.name), harmod._load(f) or []
    return None


def run(args) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)     # a run takes hours: write progress as it goes
    base = args.base.rstrip("/")
    sp = urlsplit(base)
    host = (sp.hostname or "").lower()
    origin = f"{sp.scheme}://{sp.netloc}"
    folder = Path(args.har) if args.har else None
    steps = [float(x) for x in str(args.idle_steps).split(",") if x.strip()]
    print(f"# session timeout measurement of {host} (cookie values masked; one GET per check plus one "
          "without a cookie; only this host contacted)")
    idle_h = _hars(folder, r"^(?!timeout-active)")
    if not idle_h:
        print("input missing: evidence har-timeout has no 'timeout' capture; add one with "
              f"`wstg capture {host} --role timeout` (log in, open one page only a logged-in user sees, "
              "press Enter without logging out), then collect this right away", file=sys.stderr)
        return 3
    idle = Session(*idle_h, host, origin)
    act_h = _hars(folder, r"^timeout-active$")
    active = Session(*act_h, host, origin) if act_h else None
    if not idle.sess:
        print("input missing: the 'timeout' capture sent no session cookie to this host; capture it again "
              "and log in during the walk", file=sys.stderr)
        return 3
    print(f"- idle session ('{idle.role}'): " + ", ".join(f"{n} {se.mask(v)}" for n, v in sorted(idle.sess.items())))
    if idle.expires:
        left = (idle.expires - now()) / 60
        print(f"- the cookie's own client-side expiry: {'in ' + _fmt(left) if left > 0 else _fmt(-left) + ' ago'}")
    else:
        print("- the cookie has no Max-Age/Expires (a browser-session cookie)")

    # First check: idle since the capture ended.
    v, d = idle.pick_page()
    if idle.page is None:
        print(f"- no authenticated page answered as logged in ({d}); the session may already have expired or "
              "the captured pages are public")
        print("\n# verdict: INCONCLUSIVE (capture again, open a page only a logged-in user sees, and collect "
              "this right after the capture)")
        return 0
    print(f"- page used: {idle.page['path']}")
    since = (now() - idle.last_used) / 60 if idle.last_used else None
    if since is not None:
        print(f"- check after {_fmt(since)} idle (since the capture): {v} ({d})")
    else:
        print(f"- first check (capture time unknown): {v} ({d})")
    lower, upper = (since if v == "still accepted" else None), (since if v == "rejected" else None)
    after_expiry = bool(idle.expires and v == "still accepted" and now() > idle.expires)

    a_state = "not measured (no 'timeout-active' capture)"
    a_done = active is None
    a_lower = a_upper = None
    if active and active.sess:
        av, ad = active.pick_page()
        if active.page is None or av == "rejected":
            a_done, a_state = True, f"not measured (the 'timeout-active' session does not answer as logged in: {ad})"
        else:
            print(f"- absolute: keeping the '{active.role}' session busy every {args.keepalive} min "
                  f"(page {active.page['path']})")
    elif active:
        a_done, a_state = True, "not measured (the 'timeout-active' capture sent no session cookie)"
    start = now()
    next_ping = start + args.keepalive * 60

    def keepalive_until(t_end: float) -> None:
        """Sleep until t_end, pinging the active session on schedule."""
        nonlocal next_ping, a_done, a_lower, a_upper, a_state
        while True:
            t = now()
            if t >= t_end:
                return
            if a_done or next_ping >= t_end:
                sleep(t_end - t)
                continue
            sleep(max(0.0, next_ping - t))
            av, ad = active.check()
            age = (now() - active.login_at) / 60 if active.login_at else None
            if av == "rejected":
                a_done, a_upper = True, age
                a_state = (f"rejected after {_fmt(age)} since login while in use ({ad})" if age is not None
                           else f"rejected while in use ({ad})")
            elif av == "still accepted":
                a_lower = age
            next_ping += args.keepalive * 60
            if args.pause:
                sleep(args.pause)

    deadline = start + args.max_minutes * 60
    if upper is None:
        for w in steps:
            if now() + w * 60 > deadline:
                print(f"- stopped: the next wait ({_fmt(w)}) would pass --max-minutes {args.max_minutes}")
                break
            keepalive_until(now() + w * 60)
            v, d = idle.check()
            print(f"- check after {_fmt(w)} idle: {v} ({d})")
            if v == "rejected":
                upper = w
                break
            if v == "still accepted":
                lower = max(lower or 0, w)
                after_expiry = after_expiry or bool(idle.expires and now() > idle.expires)
    if not a_done:
        keepalive_until(deadline)
        if not a_done:
            a_state = (f"still accepted after {_fmt(a_lower)} since login (no absolute timeout within the run)"
                       if a_lower is not None else "still accepted at the end of the run")

    print()
    if upper is not None:
        lo_s = _fmt(lower) if lower is not None else "0 min"
        tag = "LONG" if upper > IDLE_LONG and (lower or 0) >= IDLE_LONG else "OK"
        print(f"# idle timeout: between {lo_s} and {_fmt(upper)} (server-side) [{tag}]")
    elif lower is not None:
        print(f"# idle timeout: none within {_fmt(lower)} idle (still accepted) [LONG]")
    else:
        print("# idle timeout: not measured")
    if after_expiry:
        print("# the server still accepted the cookie after its own client-side expiry "
              "(expiry enforced only in the browser) [FAIL]")
    print(f"# absolute timeout: {a_state}"
          + (" [LONG]" if (a_upper or a_lower or 0) > ABSOLUTE_LONG else ""))
    return 0
