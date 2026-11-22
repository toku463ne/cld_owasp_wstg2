"""Record a browsing session as a HAR with a headful browser (M9 part 2).

`wstg capture TARGET` launches a real Chromium window on the Kali host through
Playwright. The tester logs in and walks the application by hand (no login
automation); the browser records every request to a HAR, and the context's
storage state (cookies, localStorage, sessionStorage) is saved too. On finish
both are stored as a new version of the target's `har-browse` evidence, which
the existing `wstg-har` analysis and the WSTG steps already read.

This replaces the manual "enable Preserve log, Save all as HAR, upload" dance;
the login and navigation stay manual. The browser window opens on the host that
runs this command, so the tester works on the Kali desktop (or over VNC).

The HAR and the storage state hold real cookies and credentials, so, like an
imported HAR, they live only in the evidence folder and are never put in a
finding or an AI chat (the AI prompt excludes HAR content, and `wstg-har`
prints no values).
"""

from __future__ import annotations

import secrets
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from . import db as dbmod
from . import entrypoints as ep
from . import evidence as evmod
from . import session as sessmod
from . import targets as tmod
from .config import Config

EVIDENCE_ID = "har-browse"
FIXATION_EVIDENCE_ID = "session-reissue-tests"
GOTO_TIMEOUT_MS = 60_000


class CaptureError(Exception):
    pass


def _stamp() -> str:
    # utcnow() is like 2026-11-08T01:21:12Z; make it file-name safe.
    return dbmod.utcnow().replace(":", "").replace("-", "").replace("T", "-").rstrip("Z")


def _start_url(target: tmod.Target, scope: tmod.Scope, override: str | None) -> str:
    url = (override or scope.base_url or f"https://{target.name}").strip().rstrip("/")
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise CaptureError(f"not a usable start URL: {url!r}")
    host = u.hostname.lower()
    port = u.port or (443 if u.scheme == "https" else 80)
    if not any(tmod.host_matches(host, p) for p in scope.allowed_hosts):
        raise tmod.ScopeError(f"start host {host} is not in the scope of {target.name}")
    if port not in scope.allowed_ports:
        raise tmod.ScopeError(f"start port {port} is not in the scope of {target.name}")
    return url


def _wait_for_finish() -> None:
    print("\n  A browser window has opened on this host.")
    print("  Log in and walk the target by hand (the recording runs in the background).")
    print("  Do NOT close the window; when you are finished, come back here and press Enter.")
    try:
        input("  Press Enter to save the recording... ")
    except EOFError:
        pass


def _drive(start_url: str, har_path: Path, state_path: Path, *, headless: bool,
           on_request, wait=_wait_for_finish) -> None:
    """Open a headful Chromium, record to `har_path`, save storage to `state_path`.

    Isolated so the rest of this module (scope checks, storing the result) is
    testable without a real browser: a test passes its own `drive`.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise CaptureError(
            "Playwright is not installed. On Kali run scripts/setup-kali.sh, or: "
            "uv sync && uv run playwright install chromium") from e
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=headless)
        except Exception as e:   # noqa: BLE001 - surface a clear hint for the missing browser binary
            raise CaptureError(
                f"cannot launch Chromium ({e}). Install the browser: "
                "uv run playwright install chromium") from e
        context = browser.new_context(record_har_path=str(har_path), record_har_mode="full",
                                      ignore_https_errors=True)
        context.on("request", lambda req: on_request(req.url))
        page = context.new_page()
        try:
            page.goto(start_url, wait_until="domcontentloaded", timeout=GOTO_TIMEOUT_MS)
        except Exception as e:   # noqa: BLE001 - navigation can fail; the tester can still browse
            print(f"  (could not open {start_url}: {e}; you can navigate manually)")
        wait()
        try:
            context.storage_state(path=str(state_path))
        except Exception as e:   # noqa: BLE001
            print(f"  (could not save storage state: {e})")
        context.close()   # flushes the HAR to disk
        browser.close()


def _wait_for_login() -> None:
    print("\n  A browser window has opened on this host, on the login page.")
    print("  Log in with a TEST account by hand (do not close the window).")
    print("  When you are logged in, come back here and press Enter.")
    try:
        input("  Press Enter once you are logged in... ")
    except EOFError:
        pass


def _drive_fixation(start_url: str, inject: str, *, headless: bool, on_request,
                    wait=_wait_for_login) -> dict:
    """Open a headful Chromium on the login page, read the session cookies, optionally
    inject a chosen value into them, let the tester log in by hand, then read the cookies
    again. Returns {before, after, final_url, injected}. Isolated so record_fixation is
    testable without a browser (a test passes its own `drive`)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise CaptureError(
            "Playwright is not installed. On Kali run scripts/setup-kali.sh, or: "
            "uv sync && uv run playwright install chromium") from e
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=headless)
        except Exception as e:   # noqa: BLE001
            raise CaptureError(f"cannot launch Chromium ({e}). Install the browser: "
                               "uv run playwright install chromium") from e
        context = browser.new_context(ignore_https_errors=True)
        context.on("request", lambda req: on_request(req.url))
        page = context.new_page()
        try:
            page.goto(start_url, wait_until="domcontentloaded", timeout=GOTO_TIMEOUT_MS)
        except Exception as e:   # noqa: BLE001
            print(f"  (could not open {start_url}: {e}; navigate to the login page manually)")
        before = context.cookies()
        injected = {}
        if inject:
            fix = [dict(c, value=inject) for c in before if sessmod.is_session_cookie(c)]
            if fix:
                context.add_cookies(fix)
                injected = {c["name"]: inject for c in fix}
                try:
                    page.reload(wait_until="domcontentloaded", timeout=GOTO_TIMEOUT_MS)
                except Exception:   # noqa: BLE001
                    pass
        wait()
        after = context.cookies()
        final_url = page.url
        context.close()
        browser.close()
    return {"before": before, "after": after, "final_url": final_url, "injected": injected}


def _cookie_header(cookies: list[dict]) -> str:
    return "; ".join(f"{c['name']}={c.get('value', '')}" for c in cookies if c.get("name"))


def record_fixation(cfg: Config, db: dbmod.Database, store: evmod.Store, target: tmod.Target, *,
                    role: str = "", actor: str = "cli", headless: bool = False,
                    start_url: str | None = None, inject: bool = True, drive=_drive_fixation) -> dict:
    """Drive a login capture and judge session fixation: reissue at login, whether an
    injected identifier survived, and whether the pre-login identifier is still accepted.
    Stores a masked summary as a new version of session-reissue-tests."""
    if target.type != "fqdn":
        raise CaptureError(f"{target.name} is a {target.type} target: a session capture needs an FQDN target")
    scope = tmod.get_scope(db, target)
    problems = tmod.scope_problems(scope)
    if problems:
        raise tmod.ScopeError(f"{target.name}: scope record does not allow capture ({'; '.join(problems)})")
    url = _start_url(target, scope, start_url)
    marker = ("wstgfix" + secrets.token_hex(6)) if inject else ""

    contacted: list[str] = []

    def on_request(req_url: str) -> None:
        contacted.append(req_url)

    snap = drive(url, marker, headless=headless, on_request=on_request)
    before_v = sessmod.session_values(snap["before"])
    after_v = sessmod.session_values(snap["after"])
    rows = sessmod.reissue_rows(before_v, after_v, snap.get("injected"))
    url_hits = sessmod.id_in_urls(contacted, set(before_v.values()) | set(after_v.values()))

    # Replay the pre-login cookies against the page the tester ended on, to see whether the
    # old identifier is still accepted. Only when that page is on an in-scope host.
    replay = _replay_old_id(snap, scope)

    summary = _fixation_summary(target, role, rows, url_hits, replay, bool(marker))
    ver = store.add_text(target, FIXATION_EVIDENCE_ID, summary,
                         f"Session fixation capture ({role or 'session'})", actor)
    fails = [r["name"] for r in rows if not r["reissued"]] + \
            [r["name"] for r in rows if r["injected_survived"]]
    return {"version": ver.version, "rows": rows, "url_hits": url_hits, "replay": replay,
            "not_reissued": [r["name"] for r in rows if not r["reissued"]],
            "injected_survived": [r["name"] for r in rows if r["injected_survived"]],
            "fail": bool(fails) or replay.get("verdict") == "still accepted"}


def _replay_old_id(snap: dict, scope: tmod.Scope) -> dict:
    final = snap.get("final_url") or ""
    u = urlsplit(final)
    host, port = (u.hostname or "").lower(), (u.port or (443 if u.scheme == "https" else 80))
    if not host or not any(tmod.host_matches(host, p) for p in scope.allowed_hosts) or port not in scope.allowed_ports:
        return {"verdict": "not tested", "detail": f"the page after login ({final or 'unknown'}) is not an in-scope URL"}
    pre, post = _cookie_header(snap["before"]), _cookie_header(snap["after"])
    if not pre or pre == post:
        return {"verdict": "not tested", "detail": "no distinct pre-login cookie to replay"}
    a_post = ep.fetch(final, post)
    a_pre = ep.fetch(final, pre)
    if a_pre.status is None:
        return {"verdict": "not tested", "detail": f"the replay request got no answer ({a_pre.error})"}
    if sessmod.looks_logged_out(a_pre.status, a_pre.location, a_pre.body):
        return {"verdict": "rejected", "detail": f"replayed pre-login cookie -> HTTP {a_pre.status} (login required)"}
    if a_pre.status == 200 and a_post.status == 200:
        return {"verdict": "still accepted",
                "detail": f"replayed pre-login cookie -> HTTP 200 like the logged-in page ({a_pre.size} vs {a_post.size} bytes)"}
    return {"verdict": "inconclusive", "detail": f"pre-login replay HTTP {a_pre.status}, logged-in HTTP {a_post.status}"}


def _fixation_summary(target, role, rows, url_hits, replay, injected: bool) -> str:
    out = [f"Session fixation (WSTG-SESS-03) for {target.name}, role {role or 'session'}.",
           "Session identifiers compared across a manual login (values masked):"]
    if not rows:
        out.append("- no session cookie was seen before or after login (check the login flow / cookie names).")
    for r in rows:
        tag = "[GOOD]" if r["reissued"] else "[FAIL]"
        out.append(f"- {r['name']}: {r['state']} {tag} (before {sessmod.mask(r['before'] or '')}, "
                   f"after {sessmod.mask(r['after'] or '')})")
        if injected and r["injected_survived"]:
            out.append(f"    injected value survived login [FAIL]: an attacker-chosen {r['name']} becomes authenticated")
    if injected:
        if not rows:
            out.append("- injection not tested (no session cookie to inject before login)")
        elif not any(r["injected_survived"] for r in rows):
            out.append("- a chosen value was injected before login into each session cookie; none survived login [GOOD]")
    out.append(f"- pre-login identifier still accepted after login: {replay['verdict']} "
               f"{'[FAIL]' if replay['verdict'] == 'still accepted' else '[GOOD]' if replay['verdict'] == 'rejected' else ''}"
               f" ({replay['detail']})")
    out.append(f"- session identifier in a URL or parameter: {'FOUND ' + str(len(url_hits)) + ' [FAIL]' if url_hits else 'none seen'}")
    for h in url_hits[:10]:
        out.append(f"    {h}")
    return "\n".join(out) + "\n"


def record_session(cfg: Config, db: dbmod.Database, store: evmod.Store, target: tmod.Target, *,
                   role: str = "", actor: str = "cli", headless: bool = False,
                   start_url: str | None = None, drive=_drive) -> dict:
    """Validate scope, drive the browser, and store the HAR + storage state.

    A domain target is passive only, so a browser capture needs an FQDN target
    with a valid, authorized scope record. Returns a summary dict.
    """
    if target.type != "fqdn":
        raise CaptureError(f"{target.name} is a {target.type} target: browser capture needs an FQDN target")
    scope = tmod.get_scope(db, target)
    problems = tmod.scope_problems(scope)
    if problems:
        raise tmod.ScopeError(f"{target.name}: scope record does not allow capture ({'; '.join(problems)})")
    url = _start_url(target, scope, start_url)

    contacted: set[tuple[str, int | None]] = set()

    def on_request(req_url: str) -> None:
        u = urlsplit(req_url)
        if u.hostname:
            contacted.add((u.hostname.lower(), u.port))

    tmp = Path(tempfile.mkdtemp(prefix="wstg-capture-"))
    label = evmod.safe_name(role) if role else "session"
    stamp = _stamp()
    har_path = tmp / f"{label}-{stamp}.har"
    state_path = tmp / f"storage-state-{label}-{stamp}.json"
    try:
        drive(url, har_path, state_path, headless=headless, on_request=on_request)
        if not har_path.is_file() or har_path.stat().st_size == 0:
            raise CaptureError("no HAR was recorded (the browser produced no traffic)")
        in_scope = sorted(h for h in contacted
                          if any(tmod.host_matches(h[0], p) for p in scope.allowed_hosts))
        out_scope = sorted(h for h in contacted if h not in set(in_scope))
        caption = f"HAR capture ({role or 'session'}) from {url}"
        if out_scope:
            caption += f"; {len(out_scope)} out-of-scope host(s) contacted"
        har_ver = store.add_file(target, EVIDENCE_ID, har_path.read_bytes(), har_path.name,
                                 caption, actor)
        state_ver = None
        if state_path.is_file() and state_path.stat().st_size:
            state_ver = store.add_file(target, EVIDENCE_ID, state_path.read_bytes(), state_path.name,
                                       f"browser storage state ({role or 'session'})", actor)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return {
        "har_file": har_path.name,
        "har_version": har_ver.version,
        "state_file": state_path.name if state_ver else None,
        "version": (state_ver or har_ver).version,
        "in_scope_hosts": [h[0] for h in in_scope],
        "out_of_scope_hosts": [h[0] for h in out_scope],
    }
