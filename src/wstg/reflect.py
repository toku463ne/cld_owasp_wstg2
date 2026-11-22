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

The marker in the response Location header is reported as HEADER-REFLECTED: the
precondition for an open redirect and for HTTP response splitting (WSTG-INPV-15, INPV-19),
to test with a CRLF/redirect payload by hand. No attack payload is sent here.

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


def _cookie_for(states: list, scheme: str, host: str) -> tuple[str, str]:
    """The first logged-in session cookie among the HAR storage states, if any."""
    for r, st in states:
        if not harmod._ANON_ROLE_RE.match(r):
            ck = ep.cookie_header(st, scheme, host, "/")
            if ck:
                return ck, r
    return "", ""


def run(args) -> int:
    base = args.base.rstrip("/")
    sp = urlsplit(base)
    origin, host = f"{sp.scheme}://{sp.netloc}", (sp.hostname or "").lower()
    cands, states = candidates(base, Path(args.katana) if args.katana else None,
                               Path(args.har) if args.har else None)
    cookie, role = _cookie_for(states, sp.scheme, host)
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
    unencoded, encoded, absent, in_header = [], [], [], []
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
        # The marker in the Location header is the precondition for an open redirect and
        # for HTTP response splitting (WSTG-INPV-15, INPV-19): worth a manual CRLF test.
        hdr = word.lower() in (a.location or "").lower()
        if hdr:
            in_header.append(label)
        occ = classify(a.body, word)
        if not occ:
            if hdr:
                print(f"- {label}: HEADER-REFLECTED into Location (HTTP {a.status}); "
                      "not in the body. Try a CRLF/redirect test here by hand (WSTG-INPV-15/19).")
            else:
                absent.append(label)
            continue
        html = "html" in (a.ctype or "")
        bad = [(ctx, risky(ctx, ch)) for ctx, ch in occ if risky(ctx, ch)]
        ctxs = ", ".join(sorted({c for c, _ in occ}))
        tail = "; also HEADER-REFLECTED into Location (try CRLF/redirect by hand)" if hdr else ""
        if bad and html:
            unencoded.append(label)
            detail = "; ".join(f"{ctx}: raw {' '.join(r)}" for ctx, r in bad)
            print(f"- {label}: REFLECTED-UNENCODED (HTTP {a.status} {a.ctype}; {detail}){tail}")
        elif bad:
            encoded.append(label)
            print(f"- {label}: reflected raw in a non-HTML response (HTTP {a.status} {a.ctype or '-'}; "
                  f"contexts {ctxs}); not rendered as HTML by itself{tail}")
        else:
            encoded.append(label)
            print(f"- {label}: reflected, encoded (HTTP {a.status} {a.ctype or '-'}; contexts {ctxs}){tail}")
    if sent and not answered:
        print(f"no request to {host} got an answer; collect again", file=sys.stderr)
        return 4
    if absent:
        print(f"- not reflected: {len(absent)} parameter(s)")
    print(f"\n# verdict: {len(unencoded)} parameter(s) REFLECTED-UNENCODED, {len(encoded)} reflected but "
          f"encoded, {len(absent)} not reflected; {len(in_header)} reflected into the Location header")
    return 0


def run_hpp(args) -> int:
    """HTTP parameter pollution (WSTG-INPV-04): send each GET parameter twice, with two
    distinct harmless markers, and report which value the application uses (first, last, or
    both). No attack payload; this shows the application's precedence rule. The front-end
    (WAF/LB) vs back-end discrepancy still needs a side-by-side manual check."""
    base = args.base.rstrip("/")
    sp = urlsplit(base)
    origin, host = f"{sp.scheme}://{sp.netloc}", (sp.hostname or "").lower()
    cands, states = candidates(base, Path(args.katana) if args.katana else None,
                               Path(args.har) if args.har else None)
    cookie, role = _cookie_for(states, sp.scheme, host)
    print(f"# HTTP parameter pollution check on {host}; each GET parameter sent twice with two "
          "harmless markers, no attack payload; GET only, only this host contacted")
    print(f"# cookies: {'logged-in session ' + role + ' (from har-browse)' if cookie else 'none (anonymous)'}")
    probes = [(path, pairs, i) for path, pairs in cands for i in range(len(pairs))]
    over = max(0, len(probes) - args.max)
    probes = probes[:args.max]
    print(f"# {len(cands)} URL(s) with a query, {len(probes)} parameter(s) checked"
          + (f", {over} over the limit of {args.max} (not sent)" if over else ""))
    if not probes:
        print("\n(no GET parameter found: collect katana-crawl, or capture har-browse first)")
        return 0
    sent = answered = 0
    counts = {"first value wins": 0, "last value wins": 0, "both values used": 0, "neither reflected": 0}
    for path, pairs, i in probes:
        base_word = "wstg" + secrets.token_hex(3)
        a_val, b_val = base_word + "aa", base_word + "bb"
        # The target parameter appears twice (first=a_val, last=b_val); other params unchanged.
        items = []
        for j, (n, v) in enumerate(pairs):
            if j == i:
                items += [(n, a_val), (n, b_val)]
            else:
                items.append((n, v))
        if sent and args.pause:
            time.sleep(args.pause)
        ans = ep.fetch(f"{origin}{path}?{urlencode(items, quote_via=quote)}", cookie)
        sent += 1
        label = f"{harmod._template(path)} ?{pairs[i][0]}"
        if ans.status is None:
            print(f"- {label}: no answer ({ans.error})")
            continue
        answered += 1
        hay = (ans.body + "\n" + (ans.location or "")).lower()
        a_in, b_in = a_val in hay, b_val in hay
        if a_in and b_in:
            rule = "both values used"
            extra = " (both markers reflected - possible concatenation; check the exact value by hand)"
        elif a_in:
            rule, extra = "first value wins", ""
        elif b_in:
            rule, extra = "last value wins", ""
        else:
            rule, extra = "neither reflected", " (cannot tell the rule from the response)"
        counts[rule] += 1
        print(f"- {label}: {rule} (HTTP {ans.status} {ans.ctype or '-'}){extra}")
    if sent and not answered:
        print(f"no request to {host} got an answer; collect again", file=sys.stderr)
        return 4
    print("\n# verdict: " + ", ".join(f"{v} {k}" for k, v in counts.items() if v)
          + ".\n# A parameter where a value is used is worth a manual front-end vs back-end "
          "check (WSTG-INPV-04): a WAF/LB that reads a different copy than the application "
          "can let a validation or authorization check be bypassed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-reflect", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--katana", help="katana-crawl evidence version folder (optional)")
    ap.add_argument("--har", help="har-browse evidence version folder (optional)")
    ap.add_argument("--hpp", action="store_true", help="HTTP parameter pollution check (WSTG-INPV-04)")
    ap.add_argument("--max", type=int, default=DEFAULT_MAX, help="parameters to check")
    ap.add_argument("--pause", type=int, default=0)
    args = ap.parse_args(argv)
    return run_hpp(args) if args.hpp else run(args)


if __name__ == "__main__":
    raise SystemExit(main())
