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

import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from . import db as dbmod
from . import evidence as evmod
from . import targets as tmod
from .config import Config

EVIDENCE_ID = "har-browse"
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
