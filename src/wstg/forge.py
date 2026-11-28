"""Forge requests by adding or overriding undisclosed parameters (WSTG-BUSL-02 step 2).

`wstg-forge --base URL [--har DIR] [--katana DIR]
            (--list | --request N --param name=value [--param ...])
            [--repeat N] [--pause S] [--agree]`

--list prints the candidate requests taken from the logged-in capture (har-browse) and the
candidate parameter names (a built-in business list plus hidden fields found in the crawl),
without sending anything. --request N resends request N as it was captured (the baseline)
and once more per --param with that parameter added or changed to the given value (the
forged request), then compares the status, the length, and whether the value is echoed in
the response. The judge (WSTG-BUSL-02 step 3) decides whether the server trusted a value it
should own; this only gathers the evidence.

Sending a forged business parameter changes the target (mutating), so the send path needs
--agree. Like the other helpers this is a Python HTTP client: it reuses the request's own
captured session cookie and contacts only the host of --base. Only run it against a target
you are authorized to test; the web Tools tab checks the scope record before each send.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from . import entrypoints as ep
from . import har as harmod

# Parameters the UI does not usually expose but the server should own. Good first guesses.
BUILTIN_PARAMS = ["price", "amount", "total", "cost", "discount", "role", "isAdmin", "admin",
                  "status", "state", "user_id", "userId", "uid", "owner", "account",
                  "quantity", "qty", "verified", "approved"]
MAX_REQUESTS = 80
MAX_RESPONSE_FILES = 300
_FORGE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Req:
    method: str
    url: str
    role: str = ""
    cookie: str = ""
    content_type: str = ""
    query: list = field(default_factory=list)        # [(name, value)]
    body_params: list = field(default_factory=list)  # [(name, value)] for form / flat JSON
    body_text: str = ""                              # raw body when it is not form/JSON params
    is_json: bool = False

    @property
    def names(self) -> list[str]:
        return [n for n, _ in self.query] + [n for n, _ in self.body_params]

    @property
    def template(self) -> str:
        return harmod._template(urlsplit(self.url).path) or "/"


def _headers(req: dict) -> dict:
    return {str(h.get("name", "")).lower(): str(h.get("value", "")) for h in req.get("headers") or []}


def _body(req: dict, content_type: str):
    post = req.get("postData") or {}
    params = [(str(p.get("name", "")), str(p.get("value", ""))) for p in post.get("params") or [] if p.get("name")]
    if params:
        return params, "", False
    text = post.get("text") or ""
    if text and "json" in (post.get("mimeType") or content_type or "").lower():
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and all(not isinstance(v, (dict, list)) for v in obj.values()):
                return [(str(k), "" if v is None else str(v)) for k, v in obj.items()], "", True
        except ValueError:
            pass
    return [], text, False


def gather_requests(base: str, har: Path | None) -> list[Req]:
    """Candidate requests from the browsing HARs: every state-changing request to the
    target host, and GETs that carry query parameters. Deduplicated by method, path
    template, and parameter names."""
    host = (urlsplit(base).hostname or "").lower()
    out: list[Req] = []
    seen = set()
    for f in ep._files(har):
        if f.suffix.lower() != ".har":
            continue
        role = harmod._role(f.name)
        for e in harmod._load(f) or []:
            req = e.get("request") or {}
            method = str(req.get("method", "")).upper()
            url = str(req.get("url", ""))
            up = urlsplit(url)
            if (up.hostname or "").lower() != host or harmod._STATIC_RE.search(up.path):
                continue
            query = parse_qsl(up.query, keep_blank_values=True)
            if method not in _FORGE_METHODS and not query:
                continue
            hdr = _headers(req)
            ct = hdr.get("content-type", "") or (req.get("postData") or {}).get("mimeType", "")
            body_params, body_text, is_json = _body(req, ct)
            key = (method, harmod._template(up.path),
                   tuple(sorted(n for n, _ in query)), tuple(sorted(n for n, _ in body_params)))
            if key in seen:
                continue
            seen.add(key)
            out.append(Req(method, url, role, hdr.get("cookie", ""), ct.split(";")[0].strip(),
                           query, body_params, body_text, is_json))
            if len(out) >= MAX_REQUESTS:
                return out
    return out


def _hidden_names(katana: Path | None) -> list[str]:
    """Hidden input field names found in crawled responses (bounded)."""
    import re
    rx = re.compile(r'(?i)<input[^>]*type=["\']?hidden["\']?[^>]*name=["\']?([A-Za-z0-9_.\[\]-]+)')
    rx2 = re.compile(r'(?i)<input[^>]*name=["\']?([A-Za-z0-9_.\[\]-]+)["\']?[^>]*type=["\']?hidden')
    names: list[str] = []
    seen = set()
    resp = (katana / "responses") if katana else None
    if not (resp and resp.is_dir()):
        return names
    for i, p in enumerate(sorted(resp.rglob("*"))):
        if i >= MAX_RESPONSE_FILES:
            break
        if not p.is_file() or p.is_symlink():
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for m in list(rx.finditer(text)) + list(rx2.finditer(text)):
            n = m.group(1)
            if n not in seen:
                seen.add(n)
                names.append(n)
    return names


def candidate_params(katana: Path | None) -> list[str]:
    out, seen = [], set()
    for n in BUILTIN_PARAMS + _hidden_names(katana):
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _set(pairs: list, name: str, value: str) -> tuple[list, bool]:
    """Pairs with `name` set to value (overriding if present, else appended). Also
    returns whether it overrode an existing parameter."""
    out, found = [], False
    for n, v in pairs:
        if n == name:
            out.append((n, value))
            found = True
        else:
            out.append((n, v))
    if not found:
        out.append((name, value))
    return out, found


def _send(r: Req, query: list, body_params: list, body_text: str, is_json: bool) -> ep.Answer:
    sp = urlsplit(r.url)
    url = f"{sp.scheme}://{sp.netloc}{sp.path}"
    if query:
        url += "?" + urlencode(query, quote_via=quote)
    extra, data = {}, None
    if is_json:
        data = json.dumps(dict(body_params)).encode()
        extra["Content-Type"] = "application/json"
    elif body_params:
        data = urlencode(body_params, quote_via=quote).encode()
        extra["Content-Type"] = "application/x-www-form-urlencoded"
    elif body_text:
        data = body_text.encode()
        if r.content_type:
            extra["Content-Type"] = r.content_type
    return ep.fetch(url, cookie=r.cookie, extra_headers=extra or None, data=data, method=r.method)


def forge_one(r: Req, name: str, value: str) -> ep.Answer:
    """Resend r with `name` added or overridden to value, in the body when the request has
    one (or is a non-GET), otherwise in the query."""
    query, body_params = list(r.query), list(r.body_params)
    if r.body_params or r.is_json or (r.method != "GET" and not r.query):
        body_params, _ = _set(body_params, name, value)
    else:
        query, _ = _set(query, name, value)
    return _send(r, query, body_params, r.body_text, r.is_json)


@dataclass
class Result:
    name: str
    value: str
    added: bool              # True: parameter was not in the request; False: overridden
    answer: ep.Answer
    echoed: bool             # the value appears in the forged response but not the baseline


def run_variants(r: Req, params: list[tuple[str, str]], repeat: int, pause: float,
                 should_stop=lambda: False) -> tuple[ep.Answer, list[Result]]:
    """Baseline (as captured) and one forged send per (name, value). `repeat` is ignored
    beyond the first send; each forged request is sent once."""
    base = _send(r, r.query, r.body_params, r.body_text, r.is_json)
    results = []
    for name, value in params:
        if should_stop():
            break
        if pause:
            time.sleep(pause)
        existing = name in r.names
        ans = forge_one(r, name, value)
        echoed = bool(value) and value in (ans.body or "") and value not in (base.body or "")
        results.append(Result(name, value, not existing, ans, echoed))
    return base, results


def _parse_params(items: list[str]) -> list[tuple[str, str]]:
    out = []
    for it in items:
        name, sep, value = it.partition("=")
        name = name.strip()
        if not name:
            continue
        out.append((name, value if sep else "1"))
    return out


def run(args) -> int:
    base = args.base.rstrip("/")
    har = Path(args.har) if args.har else None
    katana = Path(args.katana) if args.katana else None
    reqs = gather_requests(base, har)

    if args.list:
        print(f"# {len(reqs)} candidate request(s) from the capture (no request sent). "
              "Forge with --request N (repeatable) or --all, plus --param name=value.")
        for i, r in enumerate(reqs, 1):
            where = harmod._template(urlsplit(r.url).path) or "/"
            params = ",".join(r.names) or "-"
            print(f"{i}\t{r.method} {where}\tparams={params}\trole={r.role or 'anonymous'}")
        print("\n# candidate parameter names (built-in + hidden fields in the crawl):")
        print("  " + " ".join(candidate_params(katana)))
        if not reqs:
            print("\n(no suitable request in har-browse: collect a logged-in capture first)")
        return 0

    chosen = list(range(1, len(reqs) + 1)) if args.all else sorted(set(args.request))
    if not chosen:
        print("give --request N (repeatable) or --all", file=sys.stderr)
        return 2
    bad = [n for n in chosen if not 1 <= n <= len(reqs)]
    if bad:
        print(f"--request {bad[0]} is out of range 1..{len(reqs)} (run --list)", file=sys.stderr)
        return 2
    params = _parse_params(args.param)
    if not params:
        print("give at least one --param name=value", file=sys.stderr)
        return 2
    if not args.agree:
        print("forging a request may change the target; pass --agree to confirm the owner agreed", file=sys.stderr)
        return 2

    stop = Path(args.stop_file) if args.stop_file else None
    answered = 0
    print(f"# forge {len(chosen)} request(s), baseline then one forged request per parameter; "
          "Python HTTP client, only this host" + (f"; ~{args.pause}s between requests" if args.pause else "") + ".")
    for pos, n in enumerate(chosen, 1):
        if stop and stop.is_file():
            print(f"\n# stopped: {pos - 1}/{len(chosen)} request(s) done.", flush=True)
            break
        r = reqs[n - 1]
        # Print the parameter names too: several requests often share a path (Manager.aspx)
        # and only their parameters tell them apart, so the evidence must record them.
        print(f"\n[{pos}/{len(chosen)}] #{n} {r.method} {harmod._template(urlsplit(r.url).path) or '/'}"
              f"  params={','.join(r.names) or '-'}  (role {r.role or 'anonymous'})", flush=True)
        base_ans = _send(r, r.query, r.body_params, r.body_text, r.is_json)
        print(f"  baseline       : {base_ans.short()}", flush=True)
        if base_ans.status is None:
            print("  (no answer; skipping its variants)", flush=True)
            continue
        answered += 1
        for name, value in params:
            if stop and stop.is_file():
                break
            if args.pause:
                time.sleep(args.pause)
            existing = name in r.names
            ans = forge_one(r, name, value)
            echoed = bool(value) and value in (ans.body or "") and value not in (base_ans.body or "")
            verb = "overrode" if existing else "added"
            if ans.status is None:
                note = "no answer"
            else:
                dlen = ans.size - base_ans.size
                note = (f"{ans.status}" + (f", {'+' if dlen >= 0 else ''}{dlen} bytes vs baseline" if dlen else ", same length")
                        + (", value echoed in the response" if echoed else ""))
            print(f"  {verb} {name}={value!r}: {note}", flush=True)
    if not answered:
        print("\nno baseline got an answer; check the scope and the capture.", file=sys.stderr)
        return 4
    print("\n# Read these with the judge (step 3): a changed result or an echoed value may mean the "
          "server trusted the client value. Record it in forge-request-tests.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-forge", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--har", help="har-browse evidence version folder")
    ap.add_argument("--katana", help="katana-crawl evidence version folder (for hidden field names)")
    ap.add_argument("--list", action="store_true", help="list candidate requests and parameters, send nothing")
    ap.add_argument("--request", type=int, action="append", default=[], metavar="N",
                    help="1-based request to forge (repeatable; see --list)")
    ap.add_argument("--all", action="store_true", help="forge every candidate request (collect all at once)")
    ap.add_argument("--param", action="append", default=[], metavar="NAME=VALUE",
                    help="parameter to add or override (repeatable)")
    ap.add_argument("--repeat", type=int, default=1, help="(reserved; each request is sent once)")
    ap.add_argument("--pause", type=float, default=0, help="seconds between requests")
    ap.add_argument("--stop-file", help="stop gracefully as soon as this file exists")
    ap.add_argument("--agree", action="store_true", help="confirm the owner agreed (forging may change the target)")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
