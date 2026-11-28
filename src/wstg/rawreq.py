"""Raw and malformed request probe for WSTG-INPV-16 step 2.

Two families, both contacting only the host of --base (GET only except the method probe;
redirects are not followed; TLS is not verified):

  normalize  For each candidate path that the server blocks (401/403/404), send a battery
             of path-normalisation variants (case, trailing dot/slash, dot segments,
             encoded separators, a semicolon parameter) and flag SUSPECTED-bypass when a
             variant is NOT blocked - the front end and the back end normalised the path
             differently, so a front-end restriction can be passed. Candidate paths come
             from the crawl and from --path (the owner's should-be-blocked internal paths).

  parser     A fixed set of malformed requests to the base path - a duplicate Host, a
             duplicate Content-Length, bare-LF line endings, an unrelated Host, and an
             unknown method - and, only with --agree-oversized, one header whose size is
             raised gradually to a cap. Flags SUSPECTED-parser when a smuggling/routing
             precondition is accepted (a duplicate header or bare-LF request answered 2xx/3xx)
             or the server accepts the largest header. The WSTG-INPV-16 judge decides against
             the owner's front-end configuration (frontend-config); a blocked variant is a pass.

These send raw bytes over a socket (http.client would normalise them away), so they are an
active probe and need --agree. The judgement needs the front-end config, which is manual.

    wstg-raw --base URL [--katana DIR] [--path P ...]
             (--list | --all | --request N ...) [--agree] [--agree-oversized]
             [--pause S] [--stop-file F] [--max N]
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import har as harmod

MAX_PATHS = 40
READ_BYTES = 16 * 1024
TIMEOUT = 15.0
OVERSIZE_STEPS = (2048, 4096, 8192, 16384)      # one header value, raised gradually, capped
_BLOCKED = {401, 403, 404, 405}                 # a front-end restriction looks like one of these
_UA = "wstg-raw/1.0"


# ---- candidate paths ---------------------------------------------------------------

def _paths_from_katana(katana: Path | None) -> list[str]:
    out: list[str] = []
    if not katana:
        return out
    f = katana / "katana.txt"
    try:
        lines = f.read_text(errors="replace").splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line:
            continue
        p = urlsplit(line).path or "/"
        if p != "/":
            out.append(harmod._template(p))
    return out


def candidates(base: str, katana: Path | None, extra: list[str], cap: int = MAX_PATHS) -> list[str]:
    """Distinct candidate paths to test for a front-end bypass: the owner's --path entries
    first, then paths from the crawl, deduplicated by template and capped."""
    seen: set[str] = set()
    out: list[str] = []
    for p in list(extra) + _paths_from_katana(katana):
        p = p if p.startswith("/") else "/" + p
        key = harmod._template(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
        if len(out) >= cap:
            break
    return out


# ---- normalisation variants --------------------------------------------------------

def variants(path: str) -> list[tuple[str, str]]:
    """(label, variant-path) pairs for a path like /admin. Only the path is changed; each is
    sent verbatim (already encoded), so the front end and back end can normalise it apart."""
    p = path.rstrip("/") or "/"
    seg = p.rsplit("/", 1)[-1] or ""
    head = p[: len(p) - len(seg)]            # keeps the trailing slash before the last segment
    out = [
        ("uppercase", head + seg.upper()),
        ("trailing-slash", p + "/"),
        ("trailing-dot", p + "."),
        ("trailing-encoded-slash", p + "%2f"),
        ("double-slash", "/" + p.lstrip("/").replace("/", "//", 1)),
        ("leading-dot-segment", "/." + p),
        ("parent-dot-segment", head + "x/.." + "/" + seg),
        ("encoded-dot-segment", "/%2e" + p),
        ("semicolon-param", p + ";foo=bar"),
        ("path-param-parent", head + "app/..;/" + seg),
        ("trailing-space", p + "%20"),
        ("trailing-null-ish", p + "%00"),
    ]
    if seg and seg[0].isalpha():
        enc = "%%%02x" % ord(seg[0])
        out.append(("encoded-first-char", head + enc + seg[1:]))
    # keep each distinct and different from the canonical path
    uniq, cp = [], {}
    for label, v in out:
        if v != p and v not in cp:
            cp[v] = 1
            uniq.append((label, v))
    return uniq


# ---- raw sender --------------------------------------------------------------------

@dataclass
class Answer:
    status: int | None
    reason: str = ""
    error: str = ""


def _ctx() -> ssl.SSLContext:
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _build(method: str, path: str, headers: list[tuple[str, str]], line_end: str = "\r\n") -> bytes:
    lines = [f"{method} {path} HTTP/1.1"]
    lines += [f"{n}: {v}" for n, v in headers]
    return (line_end.join(lines) + line_end + line_end).encode("latin-1", "replace")


def send_raw(host: str, port: int, tls: bool, raw: bytes, timeout: float = TIMEOUT) -> Answer:
    """Send raw bytes to host:port (always the base target) and read the status line. The
    connection target never changes; only the request bytes do (so a bad Host header still
    goes to the base host, keeping the probe in scope)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return Answer(None, error=f"connect: {e}")
    try:
        s = _ctx().wrap_socket(sock, server_hostname=host) if tls else sock
        s.settimeout(timeout)
        s.sendall(raw)
        chunks, got = [], 0
        while got < READ_BYTES:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
            got += len(b)
            if b"\r\n\r\n" in b"".join(chunks) or b"\n\n" in b"".join(chunks):
                break
        data = b"".join(chunks)
    except OSError as e:
        return Answer(None, error=f"io: {e}")
    finally:
        try:
            s.close()
        except OSError:
            pass
    if not data:
        return Answer(None, error="no data (connection closed)")
    first = data.split(b"\n", 1)[0].decode("latin-1", "replace").strip()
    parts = first.split(None, 2)
    if len(parts) >= 2 and parts[0].upper().startswith("HTTP/") and parts[1].isdigit():
        return Answer(int(parts[1]), reason=parts[2] if len(parts) > 2 else "")
    return Answer(None, error=f"not HTTP: {first[:60]!r}")


def _get(host: str, port: int, tls: bool, path: str, extra: list[tuple[str, str]] | None = None,
         line_end: str = "\r\n") -> Answer:
    headers = [("Host", host), ("User-Agent", _UA), ("Accept", "*/*"), ("Connection", "close")]
    headers += extra or []
    return send_raw(host, port, tls, _build("GET", path, headers, line_end))


# ---- findings ----------------------------------------------------------------------

@dataclass
class Finding:
    kind: str               # normalize | parser
    name: str               # path or probe name
    verdict: str            # SUSPECTED-bypass | SUSPECTED-parser | blocked | open | info
    detail: str
    sent: int = 0


def probe_normalize(host, port, tls, path, pause, should_stop) -> Finding:
    base = _get(host, port, tls, path)
    sent = 1
    if base.status is None:
        return Finding("normalize", path, "info", f"canonical: {base.error}", sent)
    if base.status not in _BLOCKED:
        return Finding("normalize", path, "open",
                       f"canonical {base.status}: not blocked, nothing to bypass", sent)
    hits = []
    for label, v in variants(path):
        if should_stop():
            break
        if pause:
            time.sleep(pause)
        a = _get(host, port, tls, v)
        sent += 1
        if a.status is not None and a.status not in _BLOCKED and a.status < 500:
            hits.append(f"{label} {v!r} -> {a.status}")
    if hits:
        return Finding("normalize", path, "SUSPECTED-bypass",
                       f"canonical {base.status}, but " + "; ".join(hits[:4]), sent)
    return Finding("normalize", path, "blocked", f"canonical {base.status}; all variants blocked", sent)


def _parser_probes(host, port, tls, agree_oversized, pause, should_stop):
    """Yield Findings for the malformed-request battery against the base path."""
    base = _get(host, port, tls, "/")
    ok = base.status is not None
    # a smuggling/routing precondition that is accepted (2xx/3xx) is the signal
    def accepted(a: Answer) -> bool:
        return a.status is not None and a.status < 400

    specs = [
        ("duplicate-host", lambda: send_raw(host, port, tls, _build(
            "GET", "/", [("Host", host), ("Host", "wstg.invalid"),
                         ("User-Agent", _UA), ("Connection", "close")]))),
        ("duplicate-content-length", lambda: send_raw(host, port, tls, _build(
            "GET", "/", [("Host", host), ("Content-Length", "0"), ("Content-Length", "44"),
                         ("User-Agent", _UA), ("Connection", "close")]))),
        ("bare-lf-line-endings", lambda: _get(host, port, tls, "/", line_end="\n")),
        ("unrelated-host", lambda: send_raw(host, port, tls, _build(
            "GET", "/", [("Host", "wstg.invalid"), ("User-Agent", _UA), ("Connection", "close")]))),
        ("unknown-method", lambda: send_raw(host, port, tls, _build(
            "WSTGX", "/", [("Host", host), ("User-Agent", _UA), ("Connection", "close")]))),
    ]
    for name, call in specs:
        if should_stop():
            return
        if pause:
            time.sleep(pause)
        a = call()
        sent = 1
        if name in ("duplicate-host", "duplicate-content-length", "bare-lf-line-endings") and accepted(a):
            yield Finding("parser", name, "SUSPECTED-parser",
                          f"accepted with {a.status} (a front/back-end parser difference is possible)", sent)
        else:
            st = a.status if a.status is not None else f"no answer ({a.error})"
            yield Finding("parser", name, "info", f"-> {st}", sent)

    if not agree_oversized:
        yield Finding("parser", "oversized-header", "info",
                      "skipped (needs --agree-oversized; it can destabilise the parser)", 0)
        return
    last = None
    for n in OVERSIZE_STEPS:
        if should_stop():
            return
        if pause:
            time.sleep(pause)
        a = _get(host, port, tls, "/", extra=[("X-Wstg-Big", "A" * n)])
        last = (n, a)
        if a.status is None or a.status >= 400:
            yield Finding("parser", "oversized-header", "info",
                          f"a {n}-byte header gave {a.status or a.error}: a limit is enforced", 1)
            return
    if last and last[1].status is not None and last[1].status < 400:
        yield Finding("parser", "oversized-header", "SUSPECTED-parser",
                      f"a {last[0]}-byte header was still accepted ({last[1].status}): no header-size limit", 1)


# ---- CLI ---------------------------------------------------------------------------

def run(args) -> int:
    base = args.base.rstrip("/")
    sp = urlsplit(base)
    host = (sp.hostname or "").lower()
    tls = sp.scheme == "https"
    port = sp.port or (443 if tls else 80)
    cands = candidates(base, Path(args.katana) if args.katana else None, args.path or [], args.max)

    print(f"# raw/malformed request probe (WSTG-INPV-16) on {host}:{port}; GET only except the "
          "method probe; redirects not followed; the front-end config decides the verdict")
    print(f"# {len(cands)} candidate path(s) for the normalisation bypass, plus the parser battery")

    if args.list:
        for i, p in enumerate(cands, 1):
            print(f"{i}\tGET\t{p}\t(normalize)")
        print(f"{len(cands) + 1}\t-\t(parser battery: duplicate Host/Content-Length, bare-LF, "
              "unrelated Host, unknown method, oversized)\t(parser)")
        if not cands:
            print("(no candidate path: give --path for the owner's blocked internal paths, or collect katana-crawl)")
        return 0

    total = len(cands) + 1              # +1 for the parser battery
    chosen = set(range(1, total + 1)) if args.all else set(args.request)
    if not chosen:
        print("give --request N (repeatable) or --all (see --list)", file=sys.stderr)
        return 2
    if any(not 1 <= n <= total for n in chosen):
        print(f"--request out of range 1..{total} (run --list)", file=sys.stderr)
        return 2
    if not args.agree:
        print("this sends raw/malformed requests (a WAF may flag them; oversized can destabilise "
              "the parser); pass --agree", file=sys.stderr)
        return 2

    stop = Path(args.stop_file) if args.stop_file else None

    def should_stop() -> bool:
        return bool(stop and stop.is_file())

    suspected = answered = 0
    for pos, n in enumerate(sorted(chosen), 1):
        if should_stop():
            print(f"\n# stopped: {pos - 1}/{len(chosen)} done.", flush=True)
            break
        if args.pause and pos > 1:
            time.sleep(args.pause)
        if n <= len(cands):
            f = probe_normalize(host, port, tls, cands[n - 1], args.pause, should_stop)
            print(f"\n[{pos}/{len(chosen)}] #{n} normalize {f.name}", flush=True)
            if f.verdict != "info":
                answered += 1
            if f.verdict == "SUSPECTED-bypass":
                suspected += 1
            print(f"    => {f.verdict}: {f.detail} [{f.sent} requests]", flush=True)
        else:
            print(f"\n[{pos}/{len(chosen)}] #{n} parser battery", flush=True)
            for f in _parser_probes(host, port, tls, args.agree_oversized, args.pause, should_stop):
                answered += 1
                if f.verdict == "SUSPECTED-parser":
                    suspected += 1
                print(f"    {f.name}: {f.verdict} - {f.detail}", flush=True)

    if chosen and not answered:
        print(f"no request to {host} got a usable answer; check the scope and collect again", file=sys.stderr)
        return 4
    print(f"\n# verdict: {suspected} SUSPECTED lead(s). The WSTG-INPV-16 judge confirms each against "
          "the owner's front-end configuration (a blocked variant is a pass); this is not a scanner.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-raw", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--katana", help="katana-crawl evidence version folder (seeds candidate paths)")
    ap.add_argument("--path", action="append", default=[], metavar="P",
                    help="a should-be-blocked internal path to test (repeatable)")
    ap.add_argument("--list", action="store_true", help="list the candidate paths and the parser battery")
    ap.add_argument("--request", type=int, action="append", default=[], metavar="N",
                    help="1-based item to probe (repeatable; see --list)")
    ap.add_argument("--all", action="store_true", help="probe every candidate and the parser battery")
    ap.add_argument("--max", type=int, default=MAX_PATHS, help="candidate paths at most")
    ap.add_argument("--pause", type=float, default=0, help="seconds between requests")
    ap.add_argument("--stop-file", help="stop gracefully as soon as this file exists")
    ap.add_argument("--agree", action="store_true", help="confirm the owner agreed (sends raw/malformed requests)")
    ap.add_argument("--agree-oversized", action="store_true",
                    help="also raise a header's size gradually to a cap (can destabilise the parser)")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
