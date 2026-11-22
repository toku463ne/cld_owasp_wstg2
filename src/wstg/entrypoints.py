"""Entry point inventory of one web server (WSTG-INFO-06), collected automatically.

`wstg-entry --base URL [--list DIR] [--har DIR] [--katana DIR] [--ffuf DIR]
[--default DIR] [--admin DIR] [--metafiles DIR] [--wayback DIR] [--max N] [--pause S]`

Paths come from the tester's list (`entry-point-list`, one path per line) and from
other evidence that saw them: the browser HAR files, the crawl, ffuf hits, the
default/admin path checks that answered 200, robots.txt and sitemap.xml, and the web
archive (same host only). Every evidence folder is optional; a missing one is noted.

For each path (all of the tester's, then up to `--max` of the others), one GET
without cookies and one GET per logged-in role with the cookies of the browser
storage state that `wstg capture` saved in the HAR evidence. It reports status,
size, redirect, a login verdict, the forms on the page (field names only), and the
query parameter names seen in the HAR, crawl, and archive.

Safety: only the host of `--base` is contacted; GET only; redirects are not followed;
paths that look state-changing (logout, delete, ...) are listed but never requested;
TLS is not verified; WSTG_PAUSE (--pause) applies. Cookie values, field values, and
response bodies are never printed. Exit 4 when no request got an answer.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import har as harmod
from . import session as se

TIMEOUT = 10
BODY_BYTES = 512 * 1024
DEFAULT_MAX = 100
STATE_PATH_RE = re.compile(r"(logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|"
                           r"deactivate|cancel)", re.I)
LOGIN_URL_RE = re.compile(r"(login|log-in|signin|sign-in|auth|sso)", re.I)
_STAMP_RE = re.compile(r"[-_]\d{8}[-_]?\d{4,6}$")


# ---- sources ----------------------------------------------------------------------

@dataclass
class Entry:
    path: str
    sources: list[str] = field(default_factory=list)
    params: dict[str, set] = field(default_factory=dict)      # location -> names
    har_roles: set = field(default_factory=set)


class Inventory:
    def __init__(self, base: str):
        u = urlsplit(base)
        self.scheme, self.host = u.scheme, (u.hostname or "").lower()
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.base = f"{u.scheme}://{u.netloc}"
        self.entries: dict[str, Entry] = {}
        self.notes: list[str] = []

    def same_host(self, url: str) -> str | None:
        """The path (without query) of `url` when it is on the base host, else None."""
        u = urlsplit(url.strip())
        if not u.scheme:
            return None
        try:
            port = u.port or (443 if u.scheme == "https" else 80)
        except ValueError:
            return None
        if (u.hostname or "").lower() != self.host or port != self.port:
            return None
        return u.path or "/"

    def add(self, url: str, source: str, params: dict[str, list[str]] | None = None,
            role: str = "") -> None:
        path = self.same_host(url)
        if path is None or harmod._STATIC_RE.search(path):
            return
        e = self.entries.setdefault(path, Entry(path))
        if source not in e.sources:
            e.sources.append(source)
        _, _, query = url.partition("?")
        for name in (kv.split("=", 1)[0] for kv in query.split("&") if kv):
            e.params.setdefault("query", set()).add(name)
        for loc, names in (params or {}).items():
            e.params.setdefault(loc, set()).update(names)
        if role:
            e.har_roles.add(role)


def _read(path: Path) -> str:
    return path.read_text(errors="replace")


def read_list(inv: Inventory, folder: Path | None) -> None:
    for f in _files(folder):
        for line in _read(f).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            url = line if "://" in line else urljoin(inv.base + "/", line.lstrip("/"))
            if inv.same_host(url) is None:
                inv.notes.append(f"list: {line} is not on {inv.host}; skipped")
                continue
            inv.add(url, "list")


def read_har(inv: Inventory, folder: Path | None) -> list[tuple[str, dict]]:
    """Adds the HAR requests; returns [(role, storage-state dict)] found next to them."""
    states = []
    ended = set()                     # roles whose capture logs out: their session may be dead
    for f in _files(folder):
        if f.suffix.lower() == ".har" and se.logout_index(harmod._load(f) or []) is not None:
            ended.add(harmod._role(f.name))
    for f in _files(folder):
        name = re.sub(r"^\d{3}-", "", f.name)
        if f.suffix.lower() == ".har":
            role = harmod._role(f.name)
            for e in harmod._load(f) or []:
                req = e.get("request") or {}
                body, _ = harmod._body_params(req)
                params: dict[str, list[str]] = {}
                for loc, n in body:
                    params.setdefault(loc, []).append(n)
                inv.add(str(req.get("url", "")), "har", params, role)
        elif name.startswith("storage-state") and f.suffix.lower() == ".json":
            role = _STAMP_RE.sub("", name[len("storage-state"):-5].lstrip("-_")) or "session"
            if se.LOGOUT_ROLE_RE.match(role):
                continue                  # the dedicated logout capture (WSTG-SESS-06): its session ended
            if role in ended:
                inv.notes.append(f"har-browse: warning: the '{role}' capture logs out, so its session may be "
                                 "invalid now (capture the main walk without logging out)")
            try:
                states.append((role, json.loads(_read(f))))
            except ValueError:
                inv.notes.append(f"har-browse: {f.name} is not readable JSON; skipped")
    return states


def read_lines(inv: Inventory, folder: Path | None, name: str, source: str) -> None:
    if folder and (folder / name).is_file():
        text = _read(folder / name)
        if text.lstrip().startswith("<"):
            inv.notes.append(f"{source}: {name} is an error page, not a URL list; skipped")
            return
        for line in text.splitlines():
            if "://" in line:
                inv.add(line.split()[0], source)


def read_ffuf(inv: Inventory, folder: Path | None) -> None:
    if not folder or not (folder / "ffuf-content.json").is_file():
        return
    try:
        data = json.loads(_read(folder / "ffuf-content.json"))
    except ValueError:
        inv.notes.append("content-ffuf: ffuf-content.json is not readable; skipped")
        return
    for r in data.get("results") or []:
        if int(r.get("status") or 0) != 404 and r.get("url"):
            inv.add(r["url"], "ffuf")


def read_curl_checks(inv: Inventory, folder: Path | None, source: str) -> None:
    """default-content / admin-paths: "code size content-type URL" per line; 200 only."""
    if not folder or not (folder / "stdout.txt").is_file():
        return
    for line in _read(folder / "stdout.txt").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "200" and "://" in parts[-1]:
            inv.add(parts[-1], source)


def read_metafiles(inv: Inventory, folder: Path | None) -> None:
    if not folder:
        return
    robots = folder / "robots.txt"
    if robots.is_file() and not _read(robots).lstrip().startswith("<"):
        for line in _read(robots).splitlines():
            m = re.match(r"(?i)^\s*(dis)?allow\s*:\s*(/\S*)", line)
            if m and "*" not in m.group(2):
                inv.add(inv.base + m.group(2), "robots")
    sitemap = folder / "sitemap.xml"
    if sitemap.is_file():
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", _read(sitemap)):
            inv.add(loc, "sitemap")


def _files(folder: Path | None) -> list[Path]:
    """Files of an evidence version folder: items/* for manual evidence, else the folder."""
    if not folder or not folder.is_dir():
        return []
    items = folder / "items"
    return sorted(p for p in (items if items.is_dir() else folder).iterdir() if p.is_file())


# ---- requests ---------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@dataclass
class Answer:
    status: int | None
    size: int = 0
    ctype: str = ""
    location: str = ""
    body: str = ""
    error: str = ""

    def short(self) -> str:
        if self.status is None:
            return f"no answer ({self.error})"
        s = f"{self.status} {self.ctype or '-'} {self.size} bytes"
        return s + (f" -> {self.location}" if self.location else "")


def fetch(url: str, cookie: str = "", extra_headers: dict | None = None,
          data: bytes | None = None, method: str | None = None) -> Answer:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    proxy = os.environ.get(f"{url.split(':', 1)[0].lower()}_proxy", "")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
                                         _NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    headers = {"User-Agent": "wstg-entry-points"}
    if cookie:
        headers["Cookie"] = cookie
    if extra_headers:
        headers.update(extra_headers)
    try:
        try:
            resp = opener.open(urllib.request.Request(url, data=data, headers=headers, method=method),
                               timeout=TIMEOUT)
        except urllib.error.HTTPError as e:
            resp = e
        body = resp.read(BODY_BYTES)
        h = resp.headers
        out = Answer(getattr(resp, "status", None) or resp.code, len(body),
                     (h.get("Content-Type") or "").split(";")[0].strip(), h.get("Location") or "",
                     body.decode("utf-8", "replace"))
        resp.close()
        return out
    except (OSError, ValueError, http.client.HTTPException) as e:
        return Answer(None, error=str(getattr(e, "reason", e)))


def cookie_header(state: dict, scheme: str, host: str, path: str) -> str:
    """Cookie header from a Playwright storage state for one request (names and values
    go only into the request, never into the output)."""
    now = time.time()
    out = []
    for c in state.get("cookies") or []:
        dom = str(c.get("domain", "")).lower()
        if not (host == dom.lstrip(".") or (dom.startswith(".") and host.endswith(dom))):
            continue
        if not path.startswith(str(c.get("path") or "/")):
            continue
        if c.get("secure") and scheme != "https":
            continue
        exp = c.get("expires", -1)
        if isinstance(exp, (int, float)) and 0 < exp < now:
            continue
        out.append(f"{c.get('name')}={c.get('value')}")
    return "; ".join(out)


class _Forms(HTMLParser):
    """Forms on a page: action, method, field names (with hidden/file marked)."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                         "fields": [], "hidden": [], "file": []}
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select", "button") and self._cur is not None and a.get("name"):
            kind = a.get("type", "").lower()
            key = "hidden" if kind == "hidden" else "file" if kind == "file" else "fields"
            if kind not in ("submit", "button", "reset", "image") and a["name"] not in self._cur[key]:
                self._cur[key].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def forms_of(body: str) -> list[dict]:
    p = _Forms()
    try:
        p.feed(body)
    except Exception:          # malformed markup: report what was parsed
        pass
    return p.forms


def login_verdict(anon: Answer, users: list[tuple[str, Answer]], seen_only_logged_in: bool) -> str:
    if anon.status is None:
        return "unknown (no answer without cookies)"
    redirect_login = anon.status in (301, 302, 303, 307, 308) and LOGIN_URL_RE.search(anon.location or "")
    if anon.status in (401, 403) or redirect_login:
        return "yes (refused or sent to login without cookies)"
    ok_users = [a for _, a in users if a.status is not None]
    if anon.status == 200 and ok_users:
        u = ok_users[0]
        if u.status == 200 and abs(u.size - anon.size) <= max(200, u.size // 10):
            return ("OPEN: answers the same without login, but was seen only logged in - check it"
                    if seen_only_logged_in else "no (same answer without login)")
        if u.status == 200:
            return "partly (answers without login, with different content)"
    if anon.status == 200:
        return "no (answers without cookies)" + ("" if users else "; no logged-in session to compare")
    return f"unclear (status {anon.status} without cookies)"


# ---- main -------------------------------------------------------------------------

def run(args) -> int:
    inv = Inventory(args.base)
    p = lambda v: Path(v) if v else None   # noqa: E731
    sources = [("entry-point-list", args.list), ("har-browse", args.har), ("katana-crawl", args.katana),
               ("content-ffuf", args.ffuf), ("default-content", args.default), ("admin-paths", args.admin),
               ("metafiles", args.metafiles), ("wayback-urls", args.wayback)]
    read_list(inv, p(args.list))
    states = read_har(inv, p(args.har))
    read_lines(inv, p(args.katana), "katana.txt", "katana")
    read_ffuf(inv, p(args.ffuf))
    read_curl_checks(inv, p(args.default), "default-content")
    read_curl_checks(inv, p(args.admin), "admin-paths")
    read_metafiles(inv, p(args.metafiles))
    read_lines(inv, p(args.wayback), "wayback.txt", "wayback")

    print(f"# entry points of {inv.base}; GET only, redirects not followed, only {inv.host} contacted")
    print("# sources: " + ", ".join(f"{n} {'read' if v and Path(v).is_dir() else 'not collected'}"
                                    for n, v in sources))
    roles = [r for r, _ in states if not harmod._ANON_ROLE_RE.match(r)]
    print("# logged-in sessions (browser storage state of `wstg capture`): "
          + (", ".join(roles) if roles else "none; capture one to compare with and without login"))
    for n in inv.notes:
        print(f"# {n}")

    listed = [e for e in inv.entries.values() if "list" in e.sources]
    others = [e for e in inv.entries.values() if "list" not in e.sources]
    others.sort(key=lambda e: (0 if "har" in e.sources else 1, e.path))
    probe = listed + others[:args.max]
    rest = others[args.max:]
    print(f"# {len(inv.entries)} paths: {len(listed)} from the list, {len(others)} from other evidence;"
          f" {len(probe)} probed, {len(rest)} over the limit of {args.max} (listed at the end, not requested)")
    answered = 0
    sent = 0
    for e in probe:
        print()
        print(f"== {e.path}   [sources: {', '.join(e.sources)}]")
        if STATE_PATH_RE.search(e.path):
            print("   skipped: looks state-changing (logout, delete, ...); not requested")
            continue
        url = inv.base + e.path
        if sent and args.pause:
            time.sleep(args.pause)
        anon = fetch(url)
        sent += 1
        users = []
        for role, st in states:
            if harmod._ANON_ROLE_RE.match(role):
                continue
            ck = cookie_header(st, inv.scheme, inv.host, e.path)
            if not ck:
                continue
            if args.pause:
                time.sleep(args.pause)
            users.append((role, fetch(url, ck)))
            sent += 1
        answered += (anon.status is not None) + sum(a.status is not None for _, a in users)
        print(f"   without cookies: {anon.short()}")
        for role, a in users:
            note = ""
            if a.status in (301, 302, 303, 307, 308) and LOGIN_URL_RE.search(a.location or ""):
                note = "   (sent to login: the captured session may have expired; capture again)"
            print(f"   as {role}: {a.short()}{note}")
        only_logged_in = bool(e.har_roles) and not any(harmod._ANON_ROLE_RE.match(r) for r in e.har_roles)
        print(f"   login: {login_verdict(anon, users, only_logged_in)}")
        if e.params:
            print("   params: " + "; ".join(f"{loc}: {', '.join(sorted(n))}" for loc, n in sorted(e.params.items())))
        body = next((a.body for _, a in users if a.status == 200), anon.body if anon.status == 200 else "")
        for f in forms_of(body) if "html" in (anon.ctype + "".join(a.ctype for _, a in users)) else []:
            bits = [f"{f['method']} {f['action'] or e.path}"]
            if f["fields"]:
                bits.append("fields: " + ", ".join(f["fields"]))
            if f["hidden"]:
                bits.append("hidden: " + ", ".join(f["hidden"]))
            if f["file"]:
                bits.append("FILE UPLOAD: " + ", ".join(f["file"]))
            print("   form: " + "; ".join(bits))
    if rest:
        print()
        print(f"== not probed (over the limit of {args.max}; add them to the list to probe them)")
        for e in rest:
            print(f"   {e.path}   [sources: {', '.join(e.sources)}]")
    if not probe:
        print("\n(no path to probe: type paths in the list, capture HAR files, or collect the crawl)")
        return 0
    if sent and not answered:
        print(f"no request to {inv.base} got an answer; collect again", file=sys.stderr)
        return 4
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-entry", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    for opt in ("list", "har", "katana", "ffuf", "default", "admin", "metafiles", "wayback"):
        ap.add_argument(f"--{opt}", help="evidence version folder (optional)")
    ap.add_argument("--max", type=int, default=DEFAULT_MAX, help="paths from other evidence to probe")
    ap.add_argument("--pause", type=int, default=0)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
