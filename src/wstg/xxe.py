"""XXE / XML injection probe for WSTG-INPV-07 step 2 (the part that can be seen in-band).

For each XML request captured in the HAR (Content-Type application/xml, text/xml or
soap+xml), this resends two standard, harmless mutations of the body and classifies the
response, reusing the captured session and contacting only the target host:

  * structure break - a stray ``]]>``, an unmatched tag and a bare entity reference are
    injected into a text node. A new XML parser error (one absent from the baseline
    response) means the structure is not neutralised.

  * in-band XXE - a DOCTYPE declaring an *external* entity that points at a unique,
    NON-existent local path (``file:///nonexistent/wstg-<token>``), referenced from a text
    node. If that unique token comes back in the response, the parser tried to resolve the
    external entity (typically echoing a "failed to load external entity" error): external
    entity processing is enabled. The path does not exist, so no real file is ever read. A
    separate control marker first checks whether the app simply echoes the request body; if
    it does, the in-band signal is reported as unreliable rather than as a finding.

Out-of-band XXE (an ``http://`` entity to a host you control) and upload-borne XML (docx,
svg, SAML) are NOT automated here - they need an OOB listener or a crafted upload and stay
manual. This probe only confirms what is visible in-band; the WSTG-INPV-07 step-3 judge
decides from the evidence. It sends active payloads (a WAF may flag them), so the send path
needs --agree. Standard payloads only - this is not a scanner.
"""
from __future__ import annotations

import argparse
import re
import secrets
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

from . import entrypoints as ep
from . import har as harmod
from .forge import Req, _send, gather_requests

MAX_REQ = 40

_XML_CT = re.compile(r"(application|text)/[\w.+-]*xml|soap\+xml", re.I)

# XML parser error signatures (structure not well-formed). Entity-resolution strings are
# handled by the in-band token check, not here.
_XML_ERRORS = [
    r"not well.?formed", r"XML (parsing|syntax) error", r"XMLSyntaxError",
    r"org\.xml\.sax", r"SAXParseException", r"javax\.xml\.", r"lxml\.etree",
    r"xml\.etree\.ElementTree", r"ExpatError", r"\bexpat\b", r"Premature end of data",
    r"Start tag expected", r"Opening and ending tag mismatch", r"[Mm]ismatched tag",
    r"EntityRef: expecting ';'", r"xmlParseEntityRef", r"error parsing XML",
    r"DOMDocument::\w+", r"simplexml_load_string", r"System\.Xml\.Xml\w*Exception",
    r"Content is not allowed in prolog", r"must be well.?formed",
]

# Injected into a text node to break well-formedness: a stray CDATA close, an unmatched end
# then start tag, and a bare (undefined) entity reference.
_STRUCT = "]]></wstgx><wstgx>&wstgx;"
_ENT = "wstgext"


@dataclass
class Finding:
    request: Req
    verdict: str           # SUSPECTED-xxe-inband | SUSPECTED-xml-struct | inconclusive-echo | clean | no answer
    detail: str
    sent: int = 0


# ---- gathering ---------------------------------------------------------------------

def xml_requests(base: str, har: Path | None) -> list[Req]:
    """The captured requests whose body is XML, deduplicated by method and path template."""
    out, seen = [], set()
    for r in gather_requests(base, har):
        if not r.body_text or r.is_json or r.body_params:
            continue
        if not _XML_CT.search(r.content_type or "") and not _looks_xml(r.body_text):
            continue
        key = (r.method, r.template)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _looks_xml(text: str) -> bool:
    t = text.lstrip()
    return t.startswith("<?xml") or bool(re.match(r"<[A-Za-z_:]", t))


# ---- body mutation (no full XML parser; string surgery only) -----------------------

_DECL = re.compile(r"^\s*<\?xml[^>]*\?>", re.I)
_TEXT = re.compile(r">([^<>]*[^<>\s][^<>]*)<")      # a non-empty text node ">text<"
_ROOT = re.compile(r"<\s*([A-Za-z_][\w.:-]*)")


def _root_name(xml: str) -> str:
    m = _DECL.match(xml)
    body = xml[m.end():] if m else xml
    r = _ROOT.search(body)
    return r.group(1) if r else "root"


def _inject_text(xml: str, insert: str) -> str:
    """Put `insert` just inside the first text node; if there is none, before the last
    closing tag; failing that, append it."""
    m = _TEXT.search(xml)
    if m:
        return xml[:m.start(1)] + insert + xml[m.start(1):]
    i = xml.rfind("</")
    return (xml[:i] + insert + xml[i:]) if i != -1 else (xml + insert)


def _prepend(xml: str, snippet: str) -> str:
    """Put `snippet` right after the XML declaration (or at the very start)."""
    m = _DECL.match(xml)
    return (xml[:m.end()] + "\n" + snippet + xml[m.end():]) if m else (snippet + "\n" + xml)


def _xxe_body(xml: str, token: str) -> str:
    path = f"file:///nonexistent/wstg-{token}"
    doctype = f'<!DOCTYPE {_root_name(xml)} [<!ENTITY {_ENT} SYSTEM "{path}">]>'
    return _prepend(_inject_text(xml, f"&{_ENT};"), doctype)


# ---- sending and classifiers -------------------------------------------------------

def _resend(r: Req, body: str) -> ep.Answer:
    nr = replace(r, body_text=body, body_params=[], is_json=False)
    return _send(nr, nr.query, [], body, False)


def _new_signature(baseline: str, body: str) -> str:
    for rx in _XML_ERRORS:
        if re.search(rx, body or "", re.I) and not re.search(rx, baseline or "", re.I):
            return rx
    return ""


def probe(r: Req, pause: float = 0, should_stop=lambda: False) -> Finding:
    base = _resend(r, r.body_text)
    sent = 1
    if base.status is None:
        return Finding(r, "no answer", base.error, sent)

    def wait():
        if pause:
            time.sleep(pause)

    body = r.body_text

    struct = ""
    if not should_stop():
        wait()
        a = _resend(r, _inject_text(body, _STRUCT))
        sent += 1
        hit = _new_signature(base.body, a.body)
        if hit:
            struct = f"structure broken -> XML parser error ({hit})"

    # Does the app echo the raw request body? (would make the in-band XXE token unreliable)
    echo = False
    tok2 = secrets.token_hex(4)
    if not should_stop():
        wait()
        a = _resend(r, _prepend(body, f"<!--wstg-echo-{tok2}-->"))
        sent += 1
        echo = tok2 in (a.body or "") and tok2 not in (base.body or "")

    xxe = ""
    token = secrets.token_hex(4)
    if not should_stop():
        wait()
        a = _resend(r, _xxe_body(body, token))
        sent += 1
        if token in (a.body or "") and token not in (base.body or ""):
            xxe = ("external-entity resolution attempted: the unique SYSTEM path "
                   f"file:///nonexistent/wstg-{token} came back in the response")

    if xxe and not echo:
        return Finding(r, "SUSPECTED-xxe-inband",
                       xxe + (f"; also {struct}" if struct else ""), sent)
    if xxe and echo:
        return Finding(r, "inconclusive-echo",
                       "the response echoes the request body, so the in-band XXE token is unreliable; "
                       "confirm out-of-band (manual)" + (f". {struct}" if struct else ""), sent)
    if struct:
        return Finding(r, "SUSPECTED-xml-struct",
                       struct + (" (the response also echoes the body)" if echo else ""), sent)
    if echo:
        return Finding(r, "inconclusive-echo",
                       "the response echoes the request body but no XML error and no external-entity "
                       "signal came back; confirm out-of-band (manual)", sent)
    return Finding(r, "clean", "no XML parser error and no external-entity signal from the standard payloads", sent)


# ---- CLI ---------------------------------------------------------------------------

def run(args) -> int:
    base = args.base.rstrip("/")
    host = (urlsplit(base).hostname or "").lower()
    reqs = xml_requests(base, Path(args.har) if args.har else None)
    over = max(0, len(reqs) - args.max)
    reqs = reqs[:args.max]

    print(f"# XML injection / XXE probe (WSTG-INPV-07) on {host}; standard payloads only, no "
          "bypass fuzzing; reuses the captured session, contacts only this host")
    print(f"# {len(reqs)} XML request(s) to probe"
          + (f", {over} over the limit of {args.max} (skipped)" if over else "")
          + "; checks: structure break, in-band XXE (OOB and uploads stay manual)")

    if args.list:
        for i, r in enumerate(reqs, 1):
            print(f"{i}\t{r.method}\t{r.template}\t{r.content_type or 'xml'}\t(role {r.role or 'anonymous'})")
        if not reqs:
            print("(no XML request found: capture one into har-browse, then retry)")
        return 0

    chosen = set(range(1, len(reqs) + 1)) if args.all else set(args.request)
    if not chosen:
        print("give --request N (repeatable) or --all (see --list)", file=sys.stderr)
        return 2
    if any(not 1 <= n <= len(reqs) for n in chosen):
        print(f"--request out of range 1..{len(reqs)} (run --list)", file=sys.stderr)
        return 2
    if not args.agree:
        print("this sends active XML payloads (a WAF may flag them); pass --agree", file=sys.stderr)
        return 2

    stop = Path(args.stop_file) if args.stop_file else None

    def should_stop():
        return bool(stop and stop.is_file())

    suspected = answered = 0
    for pos, n in enumerate(sorted(chosen), 1):
        if should_stop():
            print(f"\n# stopped: {pos - 1}/{len(chosen)} done.", flush=True)
            break
        r = reqs[n - 1]
        if pos > 1 and args.pause:
            time.sleep(args.pause)
        f = probe(r, pause=args.pause, should_stop=should_stop)
        print(f"\n[{pos}/{len(chosen)}] #{n} {r.method} {r.template} "
              f"({r.content_type or 'xml'}, role {r.role or 'anonymous'})", flush=True)
        if f.verdict == "no answer":
            print(f"    no answer ({f.detail}); {f.sent} request(s)", flush=True)
            continue
        answered += 1
        if f.verdict.startswith("SUSPECTED"):
            suspected += 1
            print(f"    => {f.verdict}: {f.detail} [{f.sent} requests]", flush=True)
        else:
            print(f"    => {f.verdict}: {f.detail} [{f.sent} requests]", flush=True)
    if chosen and not answered:
        print(f"no request to {host} got an answer; capture again", file=sys.stderr)
        return 4
    print(f"\n# verdict: {suspected} XML request(s) SUSPECTED. The WSTG-INPV-07 judge confirms "
          "with the evidence; out-of-band XXE and upload-borne XML are not covered here.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-xxe", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--har", help="har-browse evidence version folder (the XML requests come from it)")
    ap.add_argument("--list", action="store_true", help="list the candidate XML requests, send nothing")
    ap.add_argument("--request", type=int, action="append", default=[], metavar="N",
                    help="1-based XML request to probe (repeatable; see --list)")
    ap.add_argument("--all", action="store_true", help="probe every candidate XML request")
    ap.add_argument("--max", type=int, default=MAX_REQ, help="XML requests to probe at most")
    ap.add_argument("--pause", type=float, default=0, help="seconds between requests")
    ap.add_argument("--stop-file", help="stop gracefully as soon as this file exists")
    ap.add_argument("--agree", action="store_true", help="confirm the owner agreed (sends active payloads)")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
