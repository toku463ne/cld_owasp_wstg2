"""Replay a request recorded in Burp (or any raw HTTP request), with small changes.

`wstg-replay FILE [--scheme https|http] [--item N] [changes] [--curl | --python | --list]
             [--repeat N] [--pause S] [--out DIR] [--proxy URL] [--max-body N]`

FILE is a raw request as Burp shows it (Proxy history or Repeater: right click >
Copy to file, or select all and paste into a file), or a Burp XML export
(Proxy history: select items > right click > Save items; base64 or not). A raw
request has no scheme: https is assumed unless the Host header names port 80 or
`--scheme http` is given. `-` reads standard input.

Changes (any number, applied in this order):

    -X METHOD                change the method
    --path /new?x=1          change the path and query
    -H 'Name: value'         set a header (replaces it); -H 'Name:' removes it
    --cookie name=value      set one cookie in the Cookie header; --no-cookies drops it
    -p name=value            set a parameter where it already is (query, form body, or a
                             top-level JSON key); a new one goes to the form body of a
                             form request, else to the query
    --body TEXT / --body-file F   replace the body

Connection, Keep-Alive, TE, Transfer-Encoding, Upgrade, and Proxy-Connection are
dropped (they belong to Burp's connection, not to the request), Content-Length is
recomputed, and Accept-Encoding is reduced to gzip and deflate (which can be
decoded here). A form or JSON body loses the line break a copy and paste may add
at its end; a multipart body gets CRLF line ends back.

Output:

    (default)  send it: one line per attempt (status, size, time, title or
               Location), then the response headers and the start of the body.
               Redirects are not followed; the TLS certificate is not checked
               (like Burp). --repeat N sends it N times with --pause S between
               them. --out DIR saves request-N.txt and response-N.txt.
    --curl     print an equivalent curl command (nothing is sent)
    --python   print a standalone Python script (standard library only) that sends
               it, with a values loop to edit (nothing is sent)
    --list     list the items of a Burp XML export (nothing is sent)

The proxy is --proxy, else https_proxy / http_proxy of the environment. Exit 0
when every attempt got an answer, 4 when one got none, 2 on bad input.

Only send it to a host you are allowed to test: this tool does not read the
scope record (the web Tools tab does).
"""
from __future__ import annotations

import argparse
import base64
import gzip
import http.client
import json
import os
import re
import shlex
import socket
import ssl
import sys
import time
import zlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit
from xml.etree import ElementTree

HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "te", "transfer-encoding", "upgrade",
              "content-length", "trailer"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
MAX_BODY = 4000
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


class ReplayError(Exception):
    """The input is not a request this tool can read or change."""


@dataclass
class Request:
    method: str
    path: str                                    # path and query, as sent
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    scheme: str = "https"
    host: str = ""
    port: int = 443

    @property
    def url(self) -> str:
        default = 443 if self.scheme == "https" else 80
        hp = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{hp}{self.path}"

    def header(self, name: str) -> str:
        return next((v for k, v in self.headers if k.lower() == name.lower()), "")

    @property
    def ctype(self) -> str:
        return self.header("content-type").split(";")[0].strip().lower()

    @property
    def safe(self) -> bool:
        """True for a method that should not change the target (GET, HEAD, ...)."""
        return self.method.upper() in SAFE_METHODS

    def wire_headers(self) -> list[tuple[str, str]]:
        """Headers as they are sent: Content-Length recomputed when there is a body."""
        out = list(self.headers)
        if self.body or self.method.upper() not in SAFE_METHODS:
            out.append(("Content-Length", str(len(self.body))))
        return out

    def raw(self) -> bytes:
        head = f"{self.method} {self.path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in self.wire_headers())
        return head.encode("latin-1", "replace") + b"\r\n" + self.body


# --------------------------------------------------------------------------
# Reading


def _split_host(value: str, scheme: str | None) -> tuple[str, int | None]:
    value = value.strip()
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\](?::(\d+))?|([^:]+)(?::(\d+))?", value)
    if not m or not (m.group(1) or m.group(3)):
        raise ReplayError(f"not a host: {value!r}")
    host = (m.group(1) or m.group(3)).lower()
    port = m.group(2) or m.group(4)
    return host, int(port) if port else None


def parse_raw(data: bytes | str, scheme: str | None = None) -> Request:
    """Read a raw HTTP/1.x request (Burp's request view). `scheme` None means: https,
    unless the request line is an absolute URL or the Host header names port 80."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = data.lstrip(b"\r\n")
    m = re.search(rb"\r?\n\r?\n", data)
    head, body = (data[:m.start()], data[m.end():]) if m else (data.rstrip(b"\r\n"), b"")
    lines = head.decode("latin-1").splitlines()
    if not lines:
        raise ReplayError("empty request")
    parts = lines[0].split()
    if len(parts) < 2 or not re.fullmatch(r"[A-Za-z]+", parts[0]):
        raise ReplayError(f"first line is not a request line: {lines[0][:80]!r}")
    method, target = parts[0].upper(), parts[1]
    headers = []
    for ln in lines[1:]:
        if not ln.strip():
            continue
        if ":" not in ln:
            raise ReplayError(f"not a header line: {ln[:80]!r}")
        k, v = ln.split(":", 1)
        headers.append((k.strip(), v.strip()))
    req = Request(method=method, path=target, headers=headers, body=body)
    if re.match(r"https?://", target, re.I):          # absolute form (a request to a proxy)
        u = urlsplit(target)
        req.scheme = u.scheme.lower()
        req.host, port = u.hostname or "", u.port
        req.port = port or (443 if req.scheme == "https" else 80)
        req.path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        if not req.header("host"):
            req.headers.insert(0, ("Host", u.netloc))
    else:
        if not req.header("host"):
            raise ReplayError("no Host header (and the request line has no absolute URL)")
        host, port = _split_host(req.header("host"), scheme)
        req.host = host
        req.scheme = scheme or ("http" if port == 80 else "https")
        req.port = port or (443 if req.scheme == "https" else 80)
    if scheme:
        req.scheme = scheme
    return _tidy_body(req)


def _tidy_body(req: Request) -> Request:
    """Undo what a copy and paste does to a body: a trailing line break on a form or
    JSON body, LF line ends in a multipart body."""
    ct = req.ctype
    if ct == "application/x-www-form-urlencoded" or ct.endswith("json"):
        req.body = req.body.rstrip(b"\r\n")
    elif ct.startswith("multipart/") and b"\r\n" not in req.body:
        req.body = req.body.replace(b"\n", b"\r\n")
    return req


def parse_burp_xml(data: bytes) -> list[Request]:
    """Items of a Burp 'Save items' XML export."""
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as e:
        raise ReplayError(f"not a Burp XML export: {e}") from None
    out = []
    for item in root.iter("item"):
        r = item.find("request")
        if r is None or not (r.text or "").strip():
            continue
        raw = base64.b64decode(r.text) if r.get("base64") == "true" else r.text.encode("utf-8")
        scheme = (item.findtext("protocol") or "https").strip().lower()
        req = parse_raw(raw, scheme)
        port = (item.findtext("port") or "").strip()
        host = (item.findtext("host") or "").strip().lower()
        if host:
            req.host = host
        if port.isdigit():
            req.port = int(port)
        out.append(req)
    return out


def load(data: bytes, scheme: str | None = None, item: int = 1) -> Request:
    """A raw request, or item N (1-based) of a Burp XML export."""
    if data.lstrip().startswith((b"<?xml", b"<items")):
        items = parse_burp_xml(data)
        if not items:
            raise ReplayError("the Burp XML export holds no request")
        if not 1 <= item <= len(items):
            raise ReplayError(f"--item {item}: the export holds {len(items)} request(s)")
        req = items[item - 1]
        return replace(req, scheme=scheme) if scheme else req
    return parse_raw(data, scheme)


# --------------------------------------------------------------------------
# Changes


def set_header(req: Request, line: str) -> None:
    if ":" not in line:
        raise ReplayError(f"-H needs 'Name: value': {line!r}")
    name, value = (x.strip() for x in line.split(":", 1))
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
        raise ReplayError(f"not a header name: {name!r}")
    if "\r" in value or "\n" in value:
        raise ReplayError("a header value cannot hold a line break")
    rest = [(k, v) for k, v in req.headers if k.lower() != name.lower()]
    if value:
        at = next((i for i, (k, _) in enumerate(req.headers) if k.lower() == name.lower()), None)
        if at is None:
            rest.append((name, value))
        else:
            rest.insert(min(at, len(rest)), (req.headers[at][0], value))
    req.headers = rest
    if name.lower() == "host" and value:
        req.host, port = _split_host(value, req.scheme)
        req.port = port or (443 if req.scheme == "https" else 80)


def set_cookie(req: Request, pair: str) -> None:
    if "=" not in pair:
        raise ReplayError(f"--cookie needs name=value: {pair!r}")
    name, value = pair.split("=", 1)
    jar = [c.strip() for c in req.header("cookie").split(";") if c.strip()]
    jar = [c for c in jar if c.split("=", 1)[0].strip() != name.strip()]
    jar.append(f"{name.strip()}={value}")
    set_header(req, "Cookie: " + "; ".join(jar))


def set_param(req: Request, pair: str) -> str:
    """Set a parameter where it is; returns where it went (query, form, json)."""
    if "=" not in pair:
        raise ReplayError(f"-p needs name=value: {pair!r}")
    name, value = pair.split("=", 1)
    path, _, query = req.path.partition("?")
    q = parse_qsl(query, keep_blank_values=True)
    ct = req.ctype
    form = parse_qsl(req.body.decode("latin-1"), keep_blank_values=True) \
        if ct == "application/x-www-form-urlencoded" else None
    if any(k == name for k, _ in q):
        req.path = path + "?" + urlencode([(k, value if k == name else v) for k, v in q], quote_via=quote, safe="/:@!$'()*,;")
        return "query"
    if form is not None and (any(k == name for k, _ in form) or not req.safe):
        if any(k == name for k, _ in form):
            form = [(k, value if k == name else v) for k, v in form]
        else:
            form.append((name, value))
        req.body = urlencode(form).encode("latin-1", "replace")
        return "form"
    if ct.endswith("json") and req.body:
        try:
            doc = json.loads(req.body)
        except ValueError:
            doc = None
        if isinstance(doc, dict) and name in doc:
            old = doc[name]
            doc[name] = value if isinstance(old, str) or old is None else _json_like(value, old)
            req.body = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            return "json"
    q.append((name, value))
    req.path = path + "?" + urlencode(q, quote_via=quote, safe="/:@!$'()*,;")
    return "query"


def _json_like(value: str, old):
    """A JSON value of the old value's type when the text reads as one, else the text."""
    try:
        new = json.loads(value)
    except ValueError:
        return value
    return new if type(new) is type(old) or (isinstance(old, (int, float)) and isinstance(new, (int, float))) else value


def clean(req: Request) -> Request:
    """Drop the headers of Burp's connection; reduce Accept-Encoding to what is decoded here."""
    req.headers = [(k, v) for k, v in req.headers if k.lower() not in HOP_BY_HOP]
    ae = req.header("accept-encoding")
    if ae:
        keep = [e.strip() for e in ae.split(",") if e.split(";")[0].strip().lower() in ("gzip", "deflate", "identity")]
        set_header(req, "Accept-Encoding: " + (", ".join(keep) if keep else "identity"))
    return req


def apply(req: Request, *, method: str = "", path: str = "", headers=(), cookies=(), no_cookies: bool = False,
          params=(), body: bytes | None = None) -> Request:
    """Apply the changes in the documented order; returns the cleaned request."""
    req = replace(req, headers=list(req.headers))
    if method:
        if not re.fullmatch(r"[A-Za-z]+", method):
            raise ReplayError(f"not a method: {method!r}")
        req.method = method.upper()
    if path:
        if not path.startswith("/") or any(c in path for c in " \r\n"):
            raise ReplayError("--path must start with / and hold no space or line break")
        req.path = path
    for h in headers:
        set_header(req, h)
    if no_cookies:
        set_header(req, "Cookie:")
    for c in cookies:
        set_cookie(req, c)
    if body is not None:
        req.body = body
    for p in params:
        set_param(req, p)
    return clean(req)


# --------------------------------------------------------------------------
# Sending


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    seconds: float
    encoded_size: int

    def header(self, name: str) -> str:
        return next((v for k, v in self.headers if k.lower() == name.lower()), "")

    def summary(self) -> str:
        loc = self.header("location")
        if loc:
            extra = f"-> {loc}"
        else:
            m = _TITLE_RE.search(self.body[:200000])
            extra = ("title: " + " ".join(m.group(1).decode("utf-8", "replace").split())[:100]) if m else ""
        return f"{self.status} {self.reason}  {len(self.body)} bytes  {self.seconds:.2f}s  {extra}".rstrip()

    def raw_head(self) -> str:
        return f"HTTP/1.1 {self.status} {self.reason}\n" + "".join(f"{k}: {v}\n" for k, v in self.headers)


def _decode(body: bytes, encoding: str) -> bytes:
    encoding = encoding.strip().lower()
    try:
        if encoding in ("gzip", "x-gzip"):
            return gzip.decompress(body)
        if encoding == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, zlib.error, EOFError):
        pass
    return body


def env_proxy(scheme: str) -> str:
    keys = ("https_proxy", "HTTPS_PROXY") if scheme == "https" else ("http_proxy", "HTTP_PROXY")
    return next((os.environ[k] for k in keys if os.environ.get(k)), "")


def send(req: Request, *, proxy: str = "", timeout: float = 30.0, max_read: int = 20 * 1024 * 1024) -> Response:
    """Send the request once, as is (no redirect followed, certificate not checked).
    Raises OSError (socket, TLS, timeout) or http.client.HTTPException."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    target = req.path
    if proxy:
        p = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        if req.scheme == "https":
            conn = http.client.HTTPSConnection(p.hostname, p.port or 8080, timeout=timeout, context=ctx)
            conn.set_tunnel(req.host, req.port)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 8080, timeout=timeout)
            target = req.url
    elif req.scheme == "https":
        conn = http.client.HTTPSConnection(req.host, req.port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(req.host, req.port, timeout=timeout)
    t0 = time.monotonic()
    try:
        conn.putrequest(req.method, target, skip_host=True, skip_accept_encoding=True)
        for k, v in req.wire_headers():
            conn.putheader(k, v.encode("latin-1", "replace"))
        conn.endheaders(req.body or None)
        r = conn.getresponse()
        raw = r.read(max_read) if req.method != "HEAD" else b""
        secs = time.monotonic() - t0
        headers = list(r.getheaders())
        body = _decode(raw, r.getheader("content-encoding") or "")
        return Response(r.status, r.reason, headers, body, secs, len(raw))
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Equivalent commands


def _bash_quote(data: bytes) -> str:
    """A bash word for the bytes: plain quoting when printable, else $'...'."""
    text = data.decode("utf-8", "replace")
    if data == text.encode("utf-8") and all(c.isprintable() or c == " " for c in text):
        return shlex.quote(text)
    out = []
    for b in data:
        c = chr(b)
        if c in "\\'":
            out.append("\\" + c)
        elif 32 <= b < 127:
            out.append(c)
        else:
            out.append(f"\\x{b:02x}")
    return "$'" + "".join(out) + "'"


def to_curl(req: Request, proxy: str = "") -> str:
    first = "curl -sk -i --http1.1 --path-as-is"
    lines = []
    if proxy:
        lines.append(f"-x {shlex.quote(proxy)}")
    if req.method != ("POST" if req.body else "GET"):
        lines.append(f"-X {req.method}")
    for k, v in req.headers:
        if k.lower() == "host" and v.lower() == req.host:
            continue                      # curl sends it from the URL
        lines.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if req.header("accept-encoding"):
        lines.append("--compressed")
    if req.body:
        lines.append(f"--data-binary {_bash_quote(req.body)}")
    lines.append(shlex.quote(req.url))
    return " \\\n  ".join([first] + lines)


PY_TEMPLATE = '''#!/usr/bin/env python3
"""Replay of {method} {url_comment}
made by wstg-replay. Standard library only. Edit VALUES and send() below.
Send it only to a host you are allowed to test."""
import gzip, http.client, ssl, sys, time, zlib
from urllib.parse import urlencode

SCHEME, HOST, PORT = {scheme!r}, {host!r}, {port!r}
METHOD, PATH = {method!r}, {path!r}
HEADERS = [
{headers}]
BODY = {body!r}
PROXY = None          # ("127.0.0.1", 8080) to send it through Burp

# One request per value; use the value in PATH, HEADERS, or BODY in send().
VALUES = [None]
PAUSE = 1.0           # seconds between requests


def send(value):
    path, headers, body = PATH, list(HEADERS), BODY
    # e.g. body = urlencode({{"name": value}}).encode()   or   path = f"/item?id={{value}}"
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    host, port = PROXY or (HOST, PORT)
    if SCHEME == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=30, context=ctx)
        if PROXY:
            conn.set_tunnel(HOST, PORT)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=30)
        if PROXY:
            path = f"http://{{HOST}}:{{PORT}}{{path}}"
    t0 = time.monotonic()
    conn.putrequest(METHOD, path, skip_host=True, skip_accept_encoding=True)
    for k, v in headers:
        conn.putheader(k, v)
    if body or METHOD not in ("GET", "HEAD", "OPTIONS", "TRACE"):
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body or None)
    r = conn.getresponse()
    data = r.read()
    enc = (r.getheader("Content-Encoding") or "").lower()
    if enc == "gzip":
        data = gzip.decompress(data)
    elif enc == "deflate":
        data = zlib.decompress(data)
    conn.close()
    print(f"{{value!r}}: {{r.status}} {{r.reason}}  {{len(data)}} bytes  {{time.monotonic() - t0:.2f}}s"
          f"  {{r.getheader('Location') or ''}}")
    return r, data


if __name__ == "__main__":
    for i, v in enumerate(VALUES):
        if i:
            time.sleep(PAUSE)
        r, data = send(v)
    if len(VALUES) == 1:
        for k, v in r.getheaders():
            print(f"{{k}}: {{v}}")
        print()
        sys.stdout.write(data[:4000].decode("utf-8", "replace") + "\\n")
'''


def to_python(req: Request) -> str:
    headers = "".join(f"    ({k!r}, {v!r}),\n" for k, v in req.headers)
    return PY_TEMPLATE.format(method=req.method, url_comment=req.url.replace('"', "'"), scheme=req.scheme,
                              host=req.host, port=req.port, path=req.path, headers=headers, body=req.body)


# --------------------------------------------------------------------------
# Command line


def describe(req: Request) -> str:
    return f"{req.method} {req.url}  ({len(req.headers)} headers, body {len(req.body)} bytes)"


def body_preview(body: bytes, limit: int) -> str:
    text = body[:limit].decode("utf-8", "replace")
    return text + (f"\n... {len(body) - limit} more bytes" if len(body) > limit else "")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-replay", description=__doc__.split("\n\n")[0])
    ap.add_argument("file", help="raw request or Burp XML export; - for standard input")
    ap.add_argument("--scheme", choices=("https", "http"))
    ap.add_argument("--item", type=int, default=1, help="item of a Burp XML export (1-based)")
    ap.add_argument("-X", "--method", default="")
    ap.add_argument("--path", default="")
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("--cookie", action="append", default=[])
    ap.add_argument("--no-cookies", action="store_true")
    ap.add_argument("-p", "--param", action="append", default=[])
    ap.add_argument("--body")
    ap.add_argument("--body-file", type=Path)
    out = ap.add_mutually_exclusive_group()
    out.add_argument("--curl", action="store_true")
    out.add_argument("--python", action="store_true")
    out.add_argument("--list", action="store_true")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--pause", type=float, default=1.0)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--max-body", type=int, default=MAX_BODY, help="body bytes printed (0: none)")
    args = ap.parse_args(argv)
    try:
        data = sys.stdin.buffer.read() if args.file == "-" else Path(args.file).read_bytes()
        if args.list:
            items = parse_burp_xml(data) if data.lstrip().startswith((b"<?xml", b"<items")) else [parse_raw(data)]
            for i, r in enumerate(items, 1):
                print(f"{i:4}  {describe(r)}")
            return 0
        body = args.body_file.read_bytes() if args.body_file else (args.body.encode() if args.body is not None else None)
        req = apply(load(data, args.scheme, args.item), method=args.method, path=args.path, headers=args.header,
                    cookies=args.cookie, no_cookies=args.no_cookies, params=args.param, body=body)
    except (OSError, ReplayError) as e:
        print(f"wstg-replay: {e}", file=sys.stderr)
        return 2
    proxy = args.proxy if args.proxy is not None else env_proxy(req.scheme)
    if args.curl:
        print(to_curl(req, proxy))
        return 0
    if args.python:
        print(to_python(req))
        return 0
    print(f"# {describe(req)}" + (f" via {proxy}" if proxy else ""))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
    failed = 0
    last = None
    for n in range(1, max(1, args.repeat) + 1):
        if n > 1:
            time.sleep(max(0.0, args.pause))
        try:
            last = send(req, proxy=proxy, timeout=args.timeout)
            print(f"{n:4}  {last.summary()}")
        except (OSError, http.client.HTTPException) as e:
            failed += 1
            print(f"{n:4}  no answer: {e.__class__.__name__}: {e}")
            continue
        if args.out:
            (args.out / f"request-{n}.txt").write_bytes(req.raw())
            (args.out / f"response-{n}.txt").write_bytes(last.raw_head().encode("latin-1", "replace") + b"\n" + last.body)
    if last is not None and args.max_body:
        print("\n" + last.raw_head())
        print(body_preview(last.body, args.max_body))
    return 4 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
