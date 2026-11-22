"""Output-encoding check of reflected GET parameters (WSTG-INPV-01, basic defences).

`wstg-reflect --base URL [--katana DIR] [--har DIR] [--max N] [--pause S]`

A basic check of whether the application encodes what it reflects, without attack
payloads: each GET query parameter found in the crawl (katana-crawl) and the main capture
(har-browse) is sent once with a harmless marker - a random word followed by the four
characters < " ' > - keeping the other parameters unchanged. Where the marker comes back,
the tool notes the output context (HTML text, inside a tag/attribute, inside a script
block, an HTML comment) and which of the four characters came back raw, encoded, or
removed:

- UNENCODED: a character that matters in that context came back raw (in HTML text `<`;
  in an attribute a quote; in a script block a quote or `<`) on an HTML response. This
  is where reflected XSS is likely; confirm it by hand if needed.
- encoded: every occurrence came back encoded (or removed) - the basic defence holds.
- not reflected.

Only the host of `--base` is contacted; GET only; redirects are not followed; when the
HAR holds a logged-in storage state its cookies are used. Exit 4 when no request got an
answer.
"""
from __future__ import annotations

import argparse
import re
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from . import entrypoints as ep
from . import har as harmod
from . import session as se

DEFAULT_MAX = 40
SPECIALS = ['<', '"', "'", '>']
# Ways a character may come back encoded (HTML entities, JS/JSON escapes, URL encoding).
_ENC = {
    "<": ("&lt;", "&#60;", "&#060;", "&#x3c;", "\\u003c", "\\x3c", "%3c"),
    '"': ("&quot;", "&#34;", "&#034;", "&#x22;", "\\u0022", "\\x22", "\\\"", "%22"),
    "'": ("&#39;", "&#039;", "&#x27;", "&apos;", "\\u0027", "\\x27", "\\'", "%27"),
    ">": ("&gt;", "&#62;", "&#062;", "&#x3e;", "\\u003e", "\\x3e", "%3e"),
}


def chars_after(body: str, at: int) -> dict[str, str]:
    """For the specials sent after the marker word, how each came back at this occurrence:
    raw, encoded, or removed (read in order; a missing one is taken as removed)."""
    seg = body[at:at + 60]
    low = seg.lower()
    out, i = {}, 0
    for c in SPECIALS:
        if seg[i:i + 1] == c:
            out[c], i = "raw", i + 1
            continue
        enc = next((e for e in _ENC[c] if low.startswith(e, i)), None)
        if enc:
            out[c], i = "encoded", i + len(enc)
        else:
            out[c] = "removed"
    return out


def context_at(body: str, pos: int) -> str:
    """Output context of position `pos`: script, comment, attribute (inside a tag), or html."""
    before = body[:pos].lower()
    if before.rfind("<script") > before.rfind("</script"):
        return "script"
    if before.rfind("<!--") > before.rfind("-->"):
        return "comment"
    if before.rfind("<") > before.rfind(">"):
        return "attribute"
    return "html"


def classify(body: str, word: str) -> list[tuple[str, dict[str, str]]]:
    """[(context, {char: raw|encoded|removed})] per occurrence of the marker word."""
    out = []
    for m in re.finditer(re.escape(word), body):
        out.append((context_at(body, m.start()), chars_after(body, m.end())))
    return out


def risky(context: str, ch: dict[str, str]) -> list[str]:
    """The raw characters that matter in this context."""
    if context == "html":
        keys = ["<"]
    elif context == "attribute":
        keys = ['"', "'"]
    elif context == "script":
        keys = ['"', "'", "<"]
    else:
        keys = []
    return [k for k in keys if ch.get(k) == "raw"]


def candidates(base: str, katana: Path | None, har: Path | None) -> tuple[list[tuple[str, list]], list]:
    """([(path, [(name, value)...])] with a query, deduplicated by path template and
    parameter names), and the HAR storage states."""
    sp = urlsplit(base)
    host = (sp.hostname or "").lower()
    urls = []
    kat = (katana / "katana.txt") if katana else None
    if kat and kat.is_file():
        urls += [ln.split()[0] for ln in kat.read_text(errors="replace").splitlines() if "://" in ln]
    states = []
    for f in ep._files(har):
        if f.suffix.lower() == ".har":
            role = harmod._role(f.name)
            if se.DEDICATED_ROLE_RE.match(role):
                continue
            for e in harmod._load(f) or []:
                req = e.get("request") or {}
                if str(req.get("method", "")).upper() == "GET":
                    urls.append(str(req.get("url", "")))
    if har:
        states = ep.read_har(ep.Inventory(base.rstrip("/") + "/"), har)
    seen, out = set(), []
    for u in urls:
        p = urlsplit(u)
        if (p.hostname or "").lower() != host or not p.query or harmod._STATIC_RE.search(p.path):
            continue
        pairs = parse_qsl(p.query, keep_blank_values=True)
        if not pairs:
            continue
        key = (harmod._template(p.path), tuple(sorted(n for n, _ in pairs)))
        if key in seen:
            continue
        seen.add(key)
        if ep.STATE_PATH_RE.search(p.path) or se.LOGOUT_PATH_RE.search(p.path):
            continue
        out.append((p.path or "/", pairs))
    return out, states


def run(args) -> int:
    base = args.base.rstrip("/")
    sp = urlsplit(base)
    origin, host = f"{sp.scheme}://{sp.netloc}", (sp.hostname or "").lower()
    cands, states = candidates(base, Path(args.katana) if args.katana else None,
                               Path(args.har) if args.har else None)
    cookie, role = "", ""
    for r, st in states:
        if not harmod._ANON_ROLE_RE.match(r):
            ck = ep.cookie_header(st, sp.scheme, host, "/")
            if ck:
                cookie, role = ck, r
                break
    print(f"# output-encoding check of reflected GET parameters on {host}; a harmless marker "
          "(a random word followed by < \" ' >), no attack payload; GET only, only this host contacted")
    print(f"# cookies: {'logged-in session ' + role + ' (from har-browse)' if cookie else 'none (anonymous)'}")
    probes = [(path, pairs, i) for path, pairs in cands for i in range(len(pairs))]
    over = max(0, len(probes) - args.max)
    probes = probes[:args.max]
    print(f"# {len(cands)} URL(s) with a query, {len(probes)} parameter(s) checked"
          + (f", {over} over the limit of {args.max} (not sent)" if over else ""))
    if not probes:
        print("\n(no GET parameter found: collect katana-crawl, or capture har-browse while using search and filters)")
        return 0
    sent = answered = 0
    unencoded, encoded, absent = [], [], []
    for path, pairs, i in probes:
        word = "wstg" + secrets.token_hex(4)
        value = word + "".join(SPECIALS)
        q = urlencode([(n, value if j == i else v) for j, (n, v) in enumerate(pairs)], quote_via=quote)
        if sent and args.pause:
            time.sleep(args.pause)
        a = ep.fetch(f"{origin}{path}?{q}", cookie)
        sent += 1
        label = f"{harmod._template(path)} ?{pairs[i][0]}"
        if a.status is None:
            print(f"- {label}: no answer ({a.error})")
            continue
        answered += 1
        occ = classify(a.body, word)
        if not occ:
            absent.append(label)
            continue
        html = "html" in (a.ctype or "")
        bad = [(ctx, risky(ctx, ch)) for ctx, ch in occ if risky(ctx, ch)]
        ctxs = ", ".join(sorted({c for c, _ in occ}))
        if bad and html:
            unencoded.append(label)
            detail = "; ".join(f"{ctx}: raw {' '.join(r)}" for ctx, r in bad)
            print(f"- {label}: REFLECTED-UNENCODED (HTTP {a.status} {a.ctype}; {detail})")
        elif bad:
            encoded.append(label)
            print(f"- {label}: reflected raw in a non-HTML response (HTTP {a.status} {a.ctype or '-'}; "
                  f"contexts {ctxs}); not rendered as HTML by itself")
        else:
            encoded.append(label)
            print(f"- {label}: reflected, encoded (HTTP {a.status} {a.ctype or '-'}; contexts {ctxs})")
    if sent and not answered:
        print(f"no request to {host} got an answer; collect again", file=sys.stderr)
        return 4
    if absent:
        print(f"- not reflected: {len(absent)} parameter(s)")
    print(f"\n# verdict: {len(unencoded)} parameter(s) REFLECTED-UNENCODED, {len(encoded)} reflected but "
          f"encoded, {len(absent)} not reflected")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-reflect", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--katana", help="katana-crawl evidence version folder (optional)")
    ap.add_argument("--har", help="har-browse evidence version folder (optional)")
    ap.add_argument("--max", type=int, default=DEFAULT_MAX, help="parameters to check")
    ap.add_argument("--pause", type=int, default=0)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
