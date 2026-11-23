"""Record a browsing session as a HAR with a headful browser (M9 part 2).

`wstg capture TARGET` launches a real Chromium window on the Kali host through
Playwright. The tester logs in and walks the application by hand (no login
automation); the browser records every request to a HAR, and the context's
storage state (cookies, localStorage, sessionStorage) is saved too, and every
few seconds the rendered DOM of each open page of the target (the page after
JavaScript ran) is kept, newest per URL. On finish all are stored as a new version of the target's `har-browse` evidence, which
the existing `wstg-har` analysis and the WSTG steps already read. The dedicated
captures go to their own evidence: `--role logout` to `har-logout` (WSTG-SESS-06)
and `--role timeout` / `timeout-active` to `har-timeout` (WSTG-SESS-07).

This replaces the manual "enable Preserve log, Save all as HAR, upload" dance;
the login and navigation stay manual. The browser window opens on the host that
runs this command, so the tester works on the Kali desktop (or over VNC).

The HAR and the storage state hold real cookies and credentials, so, like an
imported HAR, they live only in the evidence folder and are never put in a
finding or an AI chat (the AI prompt excludes HAR content, and `wstg-har`
prints no values).
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import db as dbmod
from . import evidence as evmod
from . import targets as tmod
from .config import Config

EVIDENCE_ID = "har-browse"


def evidence_for_role(role: str) -> str:
    """The manual evidence a capture of this role is stored in."""
    r = (role or "").lower()
    if r == "logout" or r.startswith("logout-"):
        return "har-logout"
    if r == "timeout" or r.startswith("timeout-"):
        return "har-timeout"
    return EVIDENCE_ID
GOTO_TIMEOUT_MS = 60_000


class CaptureError(Exception):
    pass


DOM_EVERY_S = 3                     # seconds between DOM snapshots of the open pages
DOM_MAX_PAGE = 2 * 1024 * 1024      # characters kept per page
DOM_MAX_TOTAL = 40 * 1024 * 1024    # all snapshots (the evidence file limit is 45 MB)
DOM_MAX_PAGES = 400


def dom_path_for(har_path: Path) -> Path:
    """Where `_drive` writes the DOM snapshots that go with `har_path`."""
    return har_path.with_name(f"dom-{har_path.stem}.jsonl")


class DomRecorder:
    """The rendered page (DOM after JavaScript) of every screen the tester opens,
    newest snapshot per URL, target host only (WSTG-INFO-05: content that scripts
    build after the page loads, which the HAR holds only as scripts and JSON)."""

    def __init__(self, start_url: str):
        self.host = (urlsplit(start_url).hostname or "").lower()
        self.pages: dict[str, str] = {}

    def _ours(self, url: str) -> bool:
        u = urlsplit(url)
        h = (u.hostname or "").lower()
        return u.scheme in ("http", "https") and bool(h) and (
            h == self.host or h.endswith("." + self.host) or self.host.endswith("." + h))

    def add(self, url: str, html: str) -> None:
        url = url.split("#", 1)[0]
        if not self._ours(url):
            return
        if url not in self.pages and len(self.pages) >= DOM_MAX_PAGES:
            return
        html = html[:DOM_MAX_PAGE]
        used = sum(len(v) for k, v in self.pages.items() if k != url)
        if used + len(html) <= DOM_MAX_TOTAL:
            self.pages[url] = html

    def snap(self, page) -> None:
        try:
            self.add(page.url, page.content())
        except Exception:   # noqa: BLE001 - the page may be navigating or closed
            pass

    def write(self, path: Path) -> bool:
        if not self.pages:
            return False
        with open(path, "w", encoding="utf-8") as f:
            for url, html in self.pages.items():
                f.write(json.dumps({"url": url, "html": html}, ensure_ascii=False) + "\n")
        return True


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
           on_request, wait=_wait_for_finish, proxy: str = "") -> None:
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
            browser = pw.chromium.launch(headless=headless,
                                         proxy={"server": proxy} if proxy else None)
        except Exception as e:   # noqa: BLE001 - surface a clear hint for the missing browser binary
            raise CaptureError(
                f"cannot launch Chromium ({e}). Install the browser: "
                "uv run playwright install chromium") from e
        context = browser.new_context(record_har_path=str(har_path), record_har_mode="full",
                                      ignore_https_errors=True)
        context.on("request", lambda req: on_request(req.url))
        page = context.new_page()
        print(f"  opening {start_url}" + (f" through the proxy {proxy}" if proxy else " (no proxy)"), flush=True)
        try:
            resp = page.goto(start_url, wait_until="domcontentloaded", timeout=GOTO_TIMEOUT_MS)
            print(f"  opened: {resp.status if resp else '-'} {page.url}", flush=True)
        except Exception as e:   # noqa: BLE001 - navigation can fail; the tester can still browse
            print(f"  (could not open {start_url}: {str(e).splitlines()[0]}; check the network or proxy "
                  "of this host, or navigate manually)", flush=True)
        # The tester's Enter is read on a thread; meanwhile this thread keeps the DOM
        # of each open page (Playwright's sync API stays on this thread).
        dom = DomRecorder(start_url)
        done = threading.Event()
        threading.Thread(target=lambda: (wait(), done.set()), daemon=True).start()
        while not done.is_set():
            pages = list(context.pages)
            for pg in pages:
                dom.snap(pg)
            try:
                pages[0].wait_for_timeout(DOM_EVERY_S * 1000)
            except Exception:   # noqa: BLE001 - no page open, or it is closing
                time.sleep(DOM_EVERY_S)
        for pg in list(context.pages):
            dom.snap(pg)
        dom.write(dom_path_for(har_path))
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
        drive(url, har_path, state_path, headless=headless, on_request=on_request, proxy=cfg.http_proxy)
        if not har_path.is_file() or har_path.stat().st_size == 0:
            raise CaptureError("no HAR was recorded (the browser produced no traffic)")
        in_scope = sorted(h for h in contacted
                          if any(tmod.host_matches(h[0], p) for p in scope.allowed_hosts))
        out_scope = sorted(h for h in contacted if h not in set(in_scope))
        caption = f"HAR capture ({role or 'session'}) from {url}"
        if out_scope:
            caption += f"; {len(out_scope)} out-of-scope host(s) contacted"
        eid = evidence_for_role(role)
        har_ver = store.add_file(target, eid, har_path.read_bytes(), har_path.name,
                                 caption, actor)
        state_ver = None
        if state_path.is_file() and state_path.stat().st_size:
            state_ver = store.add_file(target, eid, state_path.read_bytes(), state_path.name,
                                       f"browser storage state ({role or 'session'})", actor)
        dom_path = dom_path_for(har_path)
        dom_ver = None
        if dom_path.is_file() and dom_path.stat().st_size:
            dom_ver = store.add_file(target, eid, dom_path.read_bytes(), dom_path.name,
                                     f"rendered pages after JavaScript ({role or 'session'})", actor)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return {
        "evidence": eid,
        "har_file": har_path.name,
        "har_version": har_ver.version,
        "state_file": state_path.name if state_ver else None,
        "dom_file": dom_path.name if dom_ver else None,
        "version": (dom_ver or state_ver or har_ver).version,
        "in_scope_hosts": [h[0] for h in in_scope],
        "out_of_scope_hosts": [h[0] for h in out_scope],
    }
