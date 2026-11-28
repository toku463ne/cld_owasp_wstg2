"""Output-encoding check of reflected GET parameters (WSTG-INPV-01, basic defences).

`wstg-reflect --base URL [--katana DIR] [--har DIR] [--max N] [--pause S]`

A basic check of whether the application encodes what it reflects, without attack
payloads: each GET query parameter found in the crawl (katana-crawl) and the main capture
(har-browse) is sent once with a harmless marker - a random word followed by the four
characters < " ' > - keeping the other parameters unchanged. Where the marker comes back,
the tool notes the output context (HTML text, inside a tag/attribute, inside a script
block, an HTML comment) and which of the four characters came back raw, encoded, or
removed:

- UNENCODED: a character that matters in that context came back raw on an HTML
  response: in HTML text `<`; in an attribute the quote around its value (`"` for a
  "-quoted value, `'` for a '-quoted one, `>` for an unquoted one; a raw `'` inside a
  "-quoted value is harmless); in a script string its own quote or `<` (</script>); in
  script code (outside a string) the value already runs as code. This is where
  reflected XSS is likely. The exact url sent and the response around the marker are
  printed under the line, so it can be shown in a browser (view source).

Each parameter is sent once per path template, in the first URL that has it (its other
parameters keep their recorded values).
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
import os
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


def attr_delim(body: str, pos: int) -> str:
    """Inside a tag: the quote of the attribute value at `pos` ('"' or "'"), "u" for an
    unquoted value, "" when `pos` is not inside an attribute value."""
    seg = body[body.rfind("<", 0, pos):pos]
    state, i = "", 0
    while i < len(seg):
        c = seg[i]
        if state in ('"', "'"):
            if c == state:
                state = ""
        elif state == "u":
            if c.isspace():
                state = ""
        elif c == "=":
            i += 1
            while i < len(seg) and seg[i].isspace():
                i += 1
            if i < len(seg):
                state = seg[i] if seg[i] in ('"', "'") else "u"
            else:
                state = "u"
            if state == "u":
                continue
        i += 1
    return state


def js_delim(body: str, pos: int) -> str:
    """Inside a script block: the quote of the JavaScript string at `pos` (', ", `),
    or "" when `pos` is in code (outside a string)."""
    low = body.lower()
    start = low.rfind("<script", 0, pos)
    start = body.find(">", start, pos) + 1 if start >= 0 else 0
    state, esc = "", False
    for c in body[start:pos]:
        if esc:
            esc = False
        elif c == "\\":
            esc = bool(state)
        elif state:
            if c == state:
                state = ""
        elif c in ('"', "'", "`"):
            state = c
    return state


def classify(body: str, word: str) -> list[tuple[str, dict[str, str], str]]:
    """[(context, {char: raw|encoded|removed}, delimiter)] per occurrence of the marker word.
    The delimiter is the attribute quote (", ', u = unquoted) or the script string quote
    ("" = script code)."""
    out = []
    for m in re.finditer(re.escape(word), body):
        ctx = context_at(body, m.start())
        delim = attr_delim(body, m.start()) if ctx == "attribute" else \
            js_delim(body, m.start()) if ctx == "script" else ""
        out.append((ctx, chars_after(body, m.end()), delim))
    return out


def risky(context: str, ch: dict[str, str], delim: str | None = None) -> list[str]:
    """The raw characters that let the value break out of where it is. In an attribute
    only the quote around the value matters (a raw ' inside "..." is harmless); in a
    script string its own quote and < (for </script>); in script code the value already
    runs as code ("code")."""
    if context == "html":
        keys = ["<"]
    elif context == "attribute":
        keys = {'"': ['"'], "'": ["'"], "u": [">"], "": ['"', "'", ">"]}.get(delim, ['"', "'"]) \
            if delim is not None else ['"', "'"]
    elif context == "script":
        if delim == "":
            return ["code"] + [k for k in ('"', "'", "<") if ch.get(k) == "raw"]
        keys = ([delim] if delim in ('"', "'") else []) + ["<"] if delim is not None else ['"', "'", "<"]
    else:
        keys = []
    return [k for k in keys if ch.get(k) == "raw"]


def where(context: str, delim: str) -> str:
    """A label such as 'attribute ("-quoted)' or 'script (in a '-string)'."""
    if context == "attribute":
        return {'"': 'attribute ("-quoted)', "'": "attribute ('-quoted)", "u": "attribute (unquoted)"}.get(
            delim, "attribute (tag)")
    if context == "script":
        return f"script (in a {delim}-string)" if delim else "script (code)"
    return context


def judge(occ: list) -> tuple[str, str]:
    """(detail of the risky occurrences or "", the contexts seen) for classify() output."""
    bad = list(dict.fromkeys((where(c, d), tuple(risky(c, ch, d))) for c, ch, d in occ if risky(c, ch, d)))
    detail = "; ".join(f"{w}: " + ("runs as code" + (", raw " if len(r) > 1 else "") if r[0] == "code" else "raw ")
                       + " ".join(x for x in r if x != "code") for w, r in bad)
    return detail, ", ".join(sorted({where(c, d) for c, _, d in occ}))


def excerpt(body: str, word: str, width: int = 70) -> str:
    """The response around the first occurrence of the marker, on one line."""
    at = body.find(word)
    if at < 0:
        return ""
    seg = body[max(0, at - width):at + len(word) + 12 + width]
    return " ".join(seg.split())


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


def probes_of(cands: list[tuple[str, list]]) -> list[tuple[str, list, int]]:
    """(path, pairs, index) to send: each parameter once per path template, in the first
    URL that has it (its other parameters keep their recorded values, so the page is a
    valid screen)."""
    seen, out = set(), []
    for path, pairs in cands:
        for i, (name, _) in enumerate(pairs):
            key = (harmod._template(path), name)
            if key not in seen:
                seen.add(key)
                out.append((path, pairs, i))
    return out


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
    probes = probes_of(cands)
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
        url = f"{origin}{path}?{q}"
        a = ep.fetch(url, cookie)
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
        detail, ctxs = judge(occ)
        bad = bool(detail)
        tail = "; also HEADER-REFLECTED into Location (try CRLF/redirect by hand)" if hdr else ""
        if bad and html:
            unencoded.append(label)
            print(f"- {label}: REFLECTED-UNENCODED (HTTP {a.status} {a.ctype}; {detail}){tail}")
            print(f"    url: {url}")
            print(f"    response: ...{excerpt(a.body, word)}...")
        elif bad:
            encoded.append(label)
            print(f"- {label}: reflected raw in a non-HTML response (HTTP {a.status} {a.ctype or '-'}; "
                  f"contexts {ctxs}); not rendered as HTML by itself{tail}")
        else:
            encoded.append(label)
            print(f"- {label}: reflected, encoded where it matters (HTTP {a.status} {a.ctype or '-'}; "
                  f"contexts {ctxs}){tail}")
    if sent and not answered:
        print(f"no request to {host} got an answer; collect again", file=sys.stderr)
        return 4
    if absent:
        print(f"- not reflected: {len(absent)} parameter(s)")
    if unencoded:
        print("\n# To show one in the browser: open its url above in the browser where you are logged in"
              + (f" as {role}" if cookie else "") + " (the other parameters are the recorded ones, so it is "
              "the real screen), then view the source (Ctrl+U) and search for the wstg word: the url and "
              "the response line above are the evidence; a screenshot of the source is optional.")
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
    probes = probes_of(cands)
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


# ---- browser confirmation (WSTG-INPV-01 step 4) -----------------------------------
#
# reflection-check (step 3) proves with a harmless marker that the dangerous characters
# come back raw. The browser confirmation sends a standard sentinel payload (a tiny inline
# script that sets a window flag, no attack, no data access) in the same parameter and
# loads it in a headless browser reusing the logged-in session: if the flag is set the
# reflection actually executes (not merely reflected), confirming reflected XSS; if not,
# an encoder, a filter, a WAF, or the page's CSP stopped it. This sends a real payload, so
# it may trip a WAF - run it by agreement.

SENTINEL_VAR = "__WSTG_XSS"
_UNENC_RE = re.compile(r"^- (?P<label>.+?): REFLECTED-UNENCODED \(HTTP \d+ [^;]+; (?P<detail>.*)\)\s*$")
# where() labels, longest first so a specific one wins over "html" as a substring.
_WHERE_TO_CTX = [
    ('script (in a "-string)', ("script", '"')), ("script (in a '-string)", ("script", "'")),
    ("script (in a `-string)", ("script", "`")), ("script (code)", ("script", "")),
    ('attribute ("-quoted)', ("attribute", '"')), ("attribute ('-quoted)", ("attribute", "'")),
    ("attribute (unquoted)", ("attribute", "u")), ("attribute (tag)", ("attribute", "")),
    ("html", ("html", "")),
]


def _context_of(detail: str) -> tuple[str, str, str]:
    """(where label, context, delimiter) from a reflection-check detail string. The first
    where() label it contains wins (detail may list several, separated by '; ')."""
    for label, (context, delim) in _WHERE_TO_CTX:
        if label in detail:
            return label, context, delim
    return "html", "html", ""


def sentinel_payload(context: str, delim: str, token: str) -> str:
    """A minimal payload that runs `window.<SENTINEL_VAR>='token'` in the given context.
    Inline <script> is used (not an image), so the page's CSP is part of what is tested."""
    js = f"window.{SENTINEL_VAR}={token!r}"
    if context == "attribute":
        out = {'"': '">', "'": "'>", "u": ">"}.get(delim, '">')
        return f"{out}<script>{js}</script>"
    if context == "script":
        return (f"{delim};{js};//" if delim in ('"', "'", "`") else f";{js};//")
    return f"<script>{js}</script>"


def parse_unencoded(text: str) -> list[dict]:
    """REFLECTED-UNENCODED items from a reflection-check stdout: [{param, url, where,
    context, delim}]. The url is the one reflection-check sent (marker value in `param`)."""
    lines = text.splitlines()
    out = []
    for i, ln in enumerate(lines):
        m = _UNENC_RE.match(ln)
        if not m:
            continue
        label = m.group("label")
        param = label.split("?", 1)[1].strip() if "?" in label else label.strip()
        where_label, context, delim = _context_of(m.group("detail"))
        url = ""
        for nxt in lines[i + 1:i + 4]:
            s = nxt.strip()
            if s.startswith("url:"):
                url = s[4:].strip()
                break
        if url:
            out.append({"param": param, "url": url, "where": where_label, "context": context, "delim": delim})
    return out


def confirm_url(item: dict, token: str) -> str:
    """The item's url with its parameter's value replaced by the sentinel payload."""
    sp = urlsplit(item["url"])
    payload = sentinel_payload(item["context"], item["delim"], token)
    pairs = [(n, payload if n == item["param"] else v) for n, v in parse_qsl(sp.query, keep_blank_values=True)]
    return f"{sp.scheme}://{sp.netloc}{sp.path}?{urlencode(pairs, quote_via=quote)}"


def _redirected(requested: str, final: str) -> bool:
    """True when the browser ended up at a different page (scheme, host, or path)."""
    a, b = urlsplit(requested), urlsplit(final)
    return (a.scheme, a.netloc, a.path.rstrip("/")) != (b.scheme, b.netloc, b.path.rstrip("/"))


def _render(url: str, state: dict | None, out_png: Path | None, proxy: str, timeout_ms: int = 15000) -> dict:
    """Load `url` in headless Chromium (reusing `state` for the session). Returns a dict:
    value (sentinel value or ""), status, errors, error, final_url, redirected. Injected
    in tests."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        return {"value": "", "status": None, "errors": [], "error": f"Playwright not installed ({e})",
                "final_url": "", "redirected": False}
    errors: list[str] = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, proxy={"server": proxy} if proxy else None)
            context = browser.new_context(storage_state=state, ignore_https_errors=True)
            page = context.new_page()
            page.on("console", lambda m: errors.append(m.text) if m.type in ("error", "warning") else None)
            page.on("dialog", lambda d: d.dismiss())
            status, final = None, url
            try:
                resp = page.goto(url, wait_until="load", timeout=timeout_ms)
                status = resp.status if resp else None
                page.wait_for_timeout(1200)
                value = page.evaluate(f"window.{SENTINEL_VAR} || ''")
                final = page.url or url
                if out_png:
                    page.screenshot(path=str(out_png))
            finally:
                context.close()
                browser.close()
            return {"value": value, "status": status, "errors": errors, "error": "",
                    "final_url": final, "redirected": _redirected(url, final)}
    except Exception as e:   # noqa: BLE001 - surface any render/launch failure as text
        return {"value": "", "status": None, "errors": errors, "error": str(e).splitlines()[0],
                "final_url": "", "redirected": False}


def run_confirm(args, render=_render) -> int:
    reflect_dir = Path(args.reflect) if args.reflect else None
    so = (reflect_dir / "stdout.txt") if reflect_dir else None
    items = parse_unencoded(so.read_text(errors="replace")) if so and so.is_file() else []
    state, role = None, ""
    if args.har:
        states = ep.read_har(ep.Inventory(args.base.rstrip("/") + "/"), Path(args.har))
        for r, st in states:
            if not harmod._ANON_ROLE_RE.match(r):
                state, role = st, r
                break

    if args.list:
        print(f"# {len(items)} REFLECTED-UNENCODED parameter(s) from reflection-check (no request sent). "
              "Confirm with --candidate N or --all.")
        for i, it in enumerate(items, 1):
            print(f"{i}\t{it['param']}\t{it['where']}\t{it['url']}")
        if not items:
            print("(none: collect reflection-check first, or no parameter was REFLECTED-UNENCODED)")
        return 0

    chosen = list(range(1, len(items) + 1)) if args.all else sorted(set(args.request))
    if not chosen:
        print("give --candidate N (repeatable) or --all", file=sys.stderr)
        return 2
    if any(not 1 <= n <= len(items) for n in chosen):
        print(f"--candidate out of range 1..{len(items)} (run --list)", file=sys.stderr)
        return 2
    if not args.agree:
        print("this sends a real XSS payload (a WAF may flag it); pass --agree to confirm the owner agreed",
              file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else None
    if out:
        out.mkdir(parents=True, exist_ok=True)
    proxy = args.proxy or os.environ.get("http_proxy", "")
    stop = Path(args.stop_file) if args.stop_file else None
    print(f"# confirm {len(chosen)} REFLECTED-UNENCODED parameter(s) in a headless browser"
          + (f" as {role}" if role else " (anonymous)") + "; standard sentinel payload, no attack.")
    confirmed = 0
    for pos, n in enumerate(chosen, 1):
        if stop and stop.is_file():
            print(f"\n# stopped: {pos - 1}/{len(chosen)} done.", flush=True)
            break
        it = items[n - 1]
        token = "WSTGXSS" + secrets.token_hex(4)
        url = confirm_url(it, token)
        png = (out / f"xss-{it['param']}-{pos}.png") if out else None
        if pos > 1 and args.pause:
            time.sleep(args.pause)
        res = render(url, state, png, proxy)
        value, status, errors, err = res["value"], res["status"], res["errors"], res["error"]
        final_url, redirected = res.get("final_url", ""), res.get("redirected", False)
        executed = value == token
        print(f"\n[{pos}/{len(chosen)}] #{n} {it['param']} ({it['where']})", flush=True)
        print(f"    payload url: {url}", flush=True)
        if err:
            print(f"    render error: {err}", flush=True)
        elif executed:
            confirmed += 1
            print(f"    => CONFIRMED-EXECUTED (HTTP {status}); the sentinel ran in the browser"
                  + (f", screenshot {png.name}" if png else ""), flush=True)
        else:
            csp = next((e for e in errors if "content security policy" in e.lower() or "csp" in e.lower()), "")
            print(f"    => NOT EXECUTED (HTTP {status}); reflected but did not run"
                  + (f" - blocked: {csp}" if csp else " (encoded, filtered, WAF, or CSP)"), flush=True)
        if not err and final_url:
            print(f"    final url: {final_url}  [{'redirected' if redirected else 'no redirect'}]", flush=True)
    print(f"\n# verdict: {confirmed}/{len(chosen)} executed. Record the confirmed ones in xss-reflected-tests.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-reflect", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    cf = sub.add_parser("confirm", help="confirm a REFLECTED-UNENCODED parameter in a headless browser (step 4)")
    cf.add_argument("--base", required=True, help="base URL of the target")
    cf.add_argument("--reflect", help="reflection-check evidence version folder (the REFLECTED-UNENCODED list)")
    cf.add_argument("--har", help="har-browse evidence version folder (for the logged-in session)")
    cf.add_argument("--out", help="folder for the screenshots")
    cf.add_argument("--list", action="store_true", help="list the REFLECTED-UNENCODED parameters, send nothing")
    cf.add_argument("--candidate", dest="request", type=int, action="append", default=[], metavar="N",
                    help="1-based parameter to confirm (repeatable; see --list)")
    cf.add_argument("--all", action="store_true", help="confirm every REFLECTED-UNENCODED parameter")
    cf.add_argument("--proxy", default="", help="proxy for the browser (default: $http_proxy)")
    cf.add_argument("--pause", type=float, default=0, help="seconds between renders")
    cf.add_argument("--stop-file", help="stop gracefully as soon as this file exists")
    cf.add_argument("--agree", action="store_true", help="confirm the owner agreed (sends a real XSS payload)")

    ap.add_argument("--base", nargs="?", help="base URL of the target (the only host contacted)")
    ap.add_argument("--katana", help="katana-crawl evidence version folder (optional)")
    ap.add_argument("--har", help="har-browse evidence version folder (optional)")
    ap.add_argument("--hpp", action="store_true", help="HTTP parameter pollution check (WSTG-INPV-04)")
    ap.add_argument("--max", type=int, default=DEFAULT_MAX, help="parameters to check")
    ap.add_argument("--pause", type=int, default=0)
    args = ap.parse_args(argv)
    if args.cmd == "confirm":
        return run_confirm(args)
    if not args.base:
        ap.error("--base is required")
    return run_hpp(args) if args.hpp else run(args)


if __name__ == "__main__":
    raise SystemExit(main())
