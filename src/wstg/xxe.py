"""XML injection / XXE probe for WSTG-INPV-07 step 2 (the part that can be seen in-band).

XML reaches an application in three shapes, and this probe finds all three from the recon
crawl (katana-crawl) and the capture (har-browse), so it works on any target without a
hand-made XML capture:

  * body     - a request whose body is XML (SOAP / REST XML POST).
  * param-xml - a parameter whose value is itself an inline XML document.
  * param-ref - a parameter that names or references an XML resource (value like
    `languages.xml`, or a name like `xml`, `xmlPreview`, `data`, `doc`, `soap`): the handler
    loads/transforms XML selected by the parameter.

For each candidate it resends two standard, harmless mutations, reusing the captured
session and contacting only the target host:

  * structure break - a stray `]]>`, an unmatched tag and a bare entity: a new XML parser
    error (absent from the baseline) means the structure is not neutralised.
  * in-band XXE - a DOCTYPE declaring an *external* entity to a unique, NON-existent local
    path (`file:///nonexistent/wstg-<token>`), referenced from a text node. If that token
    comes back in the response the parser tried to resolve the external entity: external
    entity processing is on. The path does not exist, so no real file is read. A control
    marker first checks whether the response simply echoes the value/body; if it does, the
    in-band signal is reported as inconclusive-echo rather than as a finding.

Out-of-band XXE (an `http://` entity to a host you control) and upload-borne XML (docx,
svg, SAML) are NOT automated - they need an OOB listener or a crafted upload and stay
manual. This probe only confirms what is visible in-band; the WSTG-INPV-07 step-3 judge
decides. It sends active payloads (a WAF may flag them), so the send path needs --agree.
Standard payloads only - this is not a scanner.
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
from . import inject as imod
from .forge import Req, _send, _set

MAX_REQ = 40

_XML_CT = re.compile(r"(application|text)/[\w.+-]*xml|soap\+xml", re.I)

# A parameter whose value is a reference to an XML resource (ends .xml), or whose name
# suggests it carries XML.
_XML_REF_VALUE = re.compile(r"\.xml($|[?&#])", re.I)
_XMLISH_NAME = re.compile(r"xml|soap|wsdl|xslt?|payload|(^|_)doc($|ument|_)|data|content|feed|rss|atom", re.I)

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
class Cand:
    req: Req
    kind: str            # "body" | "param-xml" | "param-ref"
    name: str = ""       # parameter name for the param-* kinds

    @property
    def where(self) -> str:
        return "body" if self.kind == "body" else f"?{self.name} ({self.kind})"


@dataclass
class Finding:
    cand: Cand
    verdict: str         # SUSPECTED-xxe-inband | SUSPECTED-xml-struct | inconclusive-echo | clean | no answer
    detail: str
    sent: int = 0


# ---- gathering ---------------------------------------------------------------------

def _looks_xml(text: str) -> bool:
    t = (text or "").lstrip()
    return t.startswith("<?xml") or bool(re.match(r"<[A-Za-z_:][\w.:-]*[\s/>]", t))


def candidates(base: str, katana: Path | None, har: Path | None, cap: int = MAX_REQ) -> list[Cand]:
    """XML entry points from the crawl and the capture: XML request bodies, parameters whose
    value is inline XML, and parameters that reference an XML resource. Deduplicated and
    capped; reuses the injection engine's request gathering (HAR requests + crawl params)."""
    out, seen = [], set()
    for r in imod.gather(base, katana, har):
        if r.body_text and not r.is_json and not r.body_params \
                and (_XML_CT.search(r.content_type or "") or _looks_xml(r.body_text)):
            key = (r.method, r.template, "body", "")
            if key not in seen:
                seen.add(key)
                out.append(Cand(r, "body"))
        for name, val in list(r.query) + list(r.body_params):
            if _looks_xml(val):
                kind = "param-xml"
            elif _XML_REF_VALUE.search(val or "") or _XMLISH_NAME.search(name or ""):
                kind = "param-ref"
            else:
                continue
            key = (r.method, r.template, kind, name)
            if key not in seen:
                seen.add(key)
                out.append(Cand(r, kind, name))
        if len(out) >= cap:
            break
    return out[:cap]


# ---- body / value mutation (no full XML parser; string surgery only) ---------------

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
    """Prepend an external-entity DOCTYPE (to a non-existent path carrying `token`) to an
    existing XML document and reference the entity from a text node."""
    path = f"file:///nonexistent/wstg-{token}"
    doctype = f'<!DOCTYPE {_root_name(xml)} [<!ENTITY {_ENT} SYSTEM "{path}">]>'
    return _prepend(_inject_text(xml, f"&{_ENT};"), doctype)


def _xxe_doc(token: str) -> str:
    """A self-contained external-entity XML document, for a parameter that has no XML of its
    own to preserve (a reference parameter)."""
    path = f"file:///nonexistent/wstg-{token}"
    return (f'<?xml version="1.0"?><!DOCTYPE wstg [<!ENTITY {_ENT} SYSTEM "{path}">]>'
            f'<wstg>&{_ENT};</wstg>')


def _struct_doc() -> str:
    return '<?xml version="1.0"?><wstg>]]></wstgx><wstgx>&wstgx;</wstg>'


# ---- sending -----------------------------------------------------------------------

def _resend_body(r: Req, body: str) -> ep.Answer:
    nr = replace(r, body_text=body, body_params=[], is_json=False)
    return _send(nr, nr.query, [], body, False)


def _param_value(r: Req, name: str) -> str:
    for n, v in list(r.body_params) + list(r.query):
        if n == name:
            return v
    return ""


def _resend_param(r: Req, name: str, value: str) -> ep.Answer | None:
    query, body_params = list(r.query), list(r.body_params)
    if any(n == name for n, _ in body_params):
        body_params, _ = _set(body_params, name, value)
    elif any(n == name for n, _ in query):
        query, _ = _set(query, name, value)
    else:
        return None
    return _send(r, query, body_params, r.body_text, r.is_json)


def _send_variant(cand: Cand, payload: str) -> ep.Answer | None:
    if cand.kind == "body":
        return _resend_body(cand.req, payload)
    return _resend_param(cand.req, cand.name, payload)


def _payloads(cand: Cand, token: str, tok2: str) -> tuple[str, str, str, str]:
    """(baseline, structure-break, echo-control, in-band-XXE) payloads for this candidate."""
    if cand.kind == "param-ref":
        base_val = _param_value(cand.req, cand.name)
        return base_val, _struct_doc(), f"wstg-echo-{tok2}", _xxe_doc(token)
    xml = cand.req.body_text if cand.kind == "body" else _param_value(cand.req, cand.name)
    return (xml, _inject_text(xml, _STRUCT), _prepend(xml, f"<!--wstg-echo-{tok2}-->"),
            _xxe_body(xml, token))


# ---- classifiers -------------------------------------------------------------------

def _new_signature(baseline: str, body: str) -> str:
    for rx in _XML_ERRORS:
        if re.search(rx, body or "", re.I) and not re.search(rx, baseline or "", re.I):
            return rx
    return ""


def probe(cand: Cand, pause: float = 0, should_stop=lambda: False) -> Finding:
    token, tok2 = secrets.token_hex(4), secrets.token_hex(4)
    base_payload, struct_payload, echo_payload, xxe_payload = _payloads(cand, token, tok2)

    base = _send_variant(cand, base_payload)
    sent = 1
    if base is None or base.status is None:
        return Finding(cand, "no answer", base.error if base else "parameter not found", sent)

    def wait():
        if pause:
            time.sleep(pause)

    struct = ""
    if not should_stop():
        wait()
        a = _send_variant(cand, struct_payload)
        sent += 1
        hit = _new_signature(base.body, a.body if a else "")
        if hit:
            struct = f"structure broken -> XML parser error ({hit})"

    echo = False
    if not should_stop():
        wait()
        a = _send_variant(cand, echo_payload)
        sent += 1
        echo = bool(a) and tok2 in (a.body or "") and tok2 not in (base.body or "")

    xxe = ""
    if not should_stop():
        wait()
        a = _send_variant(cand, xxe_payload)
        sent += 1
        if a and token in (a.body or "") and token not in (base.body or ""):
            xxe = ("external-entity resolution attempted: the unique SYSTEM path "
                   f"file:///nonexistent/wstg-{token} came back in the response")

    if xxe and not echo:
        return Finding(cand, "SUSPECTED-xxe-inband", xxe + (f"; also {struct}" if struct else ""), sent)
    if xxe and echo:
        return Finding(cand, "inconclusive-echo",
                       "the response echoes the sent value, so the in-band XXE token is unreliable; "
                       "confirm out-of-band (manual)" + (f". {struct}" if struct else ""), sent)
    if struct:
        return Finding(cand, "SUSPECTED-xml-struct",
                       struct + (" (the response also echoes the value)" if echo else ""), sent)
    if echo:
        return Finding(cand, "inconclusive-echo",
                       "the response echoes the sent value but no XML error and no external-entity "
                       "signal came back; confirm out-of-band (manual)", sent)
    return Finding(cand, "clean", "no XML parser error and no external-entity signal from the standard payloads", sent)


# ---- CLI ---------------------------------------------------------------------------

def run(args) -> int:
    base = args.base.rstrip("/")
    host = (urlsplit(base).hostname or "").lower()
    cands = candidates(base, Path(args.katana) if args.katana else None,
                       Path(args.har) if args.har else None, cap=args.max)

    print(f"# XML injection / XXE probe (WSTG-INPV-07) on {host}; standard payloads only, no "
          "bypass fuzzing; reuses the captured session, contacts only this host")
    print(f"# {len(cands)} XML entry point(s): request bodies, inline-XML parameters, and "
          "XML-reference parameters; checks: structure break, in-band XXE (OOB and uploads stay manual)")

    if args.list:
        for i, c in enumerate(cands, 1):
            print(f"{i}\t{c.req.method}\t{c.req.template}\t{c.kind}\t{c.name or (c.req.content_type or 'xml')}"
                  f"\t(role {c.req.role or 'anonymous'})")
        if not cands:
            print("(no XML entry point in the crawl or capture: no XML body, no inline-XML or "
                  "XML-reference parameter. Test XML inputs and uploads by hand.)")
        return 0

    chosen = set(range(1, len(cands) + 1)) if args.all else set(args.request)
    if not chosen:
        print("give --request N (repeatable) or --all (see --list)", file=sys.stderr)
        return 2
    if any(not 1 <= n <= len(cands) for n in chosen):
        print(f"--request out of range 1..{len(cands)} (run --list)", file=sys.stderr)
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
        c = cands[n - 1]
        if pos > 1 and args.pause:
            time.sleep(args.pause)
        f = probe(c, pause=args.pause, should_stop=should_stop)
        print(f"\n[{pos}/{len(chosen)}] #{n} {c.req.method} {c.req.template} {c.where} "
              f"(role {c.req.role or 'anonymous'})", flush=True)
        if f.verdict == "no answer":
            print(f"    no answer ({f.detail}); {f.sent} request(s)", flush=True)
            continue
        answered += 1
        if f.verdict.startswith("SUSPECTED"):
            suspected += 1
        print(f"    => {f.verdict}: {f.detail} [{f.sent} requests]", flush=True)
    if chosen and not answered:
        print(f"no request to {host} got an answer; capture again", file=sys.stderr)
        return 4
    print(f"\n# verdict: {suspected} XML entry point(s) SUSPECTED. The WSTG-INPV-07 judge confirms "
          "with the evidence; out-of-band XXE and upload-borne XML are not covered here.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-xxe", description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--katana", help="katana-crawl evidence version folder (for XML-reference parameters)")
    ap.add_argument("--har", help="har-browse evidence version folder (for XML bodies and the session)")
    ap.add_argument("--list", action="store_true", help="list the candidate XML entry points, send nothing")
    ap.add_argument("--request", type=int, action="append", default=[], metavar="N",
                    help="1-based entry point to probe (repeatable; see --list)")
    ap.add_argument("--all", action="store_true", help="probe every candidate entry point")
    ap.add_argument("--max", type=int, default=MAX_REQ, help="entry points to probe at most")
    ap.add_argument("--pause", type=float, default=0, help="seconds between requests")
    ap.add_argument("--stop-file", help="stop gracefully as soon as this file exists")
    ap.add_argument("--agree", action="store_true", help="confirm the owner agreed (sends active payloads)")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
