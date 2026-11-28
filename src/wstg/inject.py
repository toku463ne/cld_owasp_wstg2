"""Injection probe engine for the WSTG-INPV active-probe steps.

One engine, several payload packs (data). For each candidate request parameter it sends a
small, standard set of payloads appended to the parameter's value and classifies the
response - no bypass fuzzing, no scanner. The classifiers are:

  error    a database/engine error signature appears that the baseline did not have
  boolean  a TRUE payload keeps the page while a FALSE payload clearly changes it
  eval     an expression payload's computed result (an unusual number) appears
  time     a sleep payload makes the response take markedly longer, twice

It gathers the evidence; the per-WSTG AI judge decides. Sending these payloads is an
active probe (a WAF may flag it), so the send path needs --agree. Like the other helpers
it is a Python HTTP client: it reuses each request's captured session and contacts only the
host of --base.

    wstg-inject --pack sqli --base URL [--katana DIR] [--har DIR]
                (--list | --all | --request N ...) [--only name,name]
                [--agree] [--pause S] [--stop-file F] [--max N]
"""
from __future__ import annotations

import argparse
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

from . import entrypoints as ep
from . import har as harmod
from . import reflect as reflmod
from .forge import Req, _send, _set, gather_requests

MAX_PARAMS = 60
TIME_PAYLOAD_SECONDS = 5           # the delay a time payload asks for
TIME_MARGIN = 3.0                  # a hit must be at least baseline + this many seconds
BODY_SHRINK = 0.30                 # a FALSE boolean response this much shorter counts as "changed"


# ---- payload packs (data) ----------------------------------------------------------

_SQL_ERRORS = [
    r"SQL syntax", r"mysql_fetch", r"valid MySQL result", r"MySqlException", r"ORA-\d{5}",
    r"PLS-\d{5}", r"PostgreSQL.{0,40}ERROR", r"pg_query", r"Microsoft OLE DB",
    r"ODBC .{0,30}Driver", r"SQLServer JDBC", r"Unclosed quotation mark",
    r"quoted string not properly terminated", r"SQLSTATE", r"SQLite3?::", r"sqlite3.OperationalError",
    r"Warning:\s+(?:mysqli?|pg|sqlite|odbc|mssql)",
]
_LDAP_ERRORS = [r"javax\.naming", r"LDAPException", r"com\.sun\.jndi", r"Invalid DN syntax",
                r"LDAP: error code \d+", r"supplied argument is not a valid ldap"]
_XPATH_ERRORS = [r"XPathException", r"XPath (?:syntax )?error", r"SimpleXMLElement::xpath",
                 r"org\.apache\.xpath", r"MS\.Internal\.Xml", r"Expression must evaluate to a node-set"]


@dataclass
class Pack:
    key: str
    title: str
    wstg: str
    checks: list[str]                       # subset of error/boolean/eval/time
    error_payloads: list[str] = field(default_factory=list)
    error_signatures: list[str] = field(default_factory=list)
    boolean_pairs: list = field(default_factory=list)       # [(true, false)]
    eval_payloads: list = field(default_factory=list)       # [(payload, marker)]
    time_payloads: list[str] = field(default_factory=list)
    ssi_directive: str = ""                                 # an SSI directive to try
    crlf: bool = False                                      # try a CRLF header-injection probe


# An eval marker chosen to be unusual (7*191) so a coincidental match is unlikely.
_SSTI = [("${7*191}", "1337"), ("${{7*191}}", "1337"), ("{{7*191}}", "1337"),
         ("#{7*191}", "1337"), ("<%= 7*191 %>", "1337"), ("{7*191}", "1337")]

PACKS: dict[str, Pack] = {
    "sqli": Pack(
        "sqli", "SQL injection probe", "WSTG-INPV-05", ["error", "boolean", "time"],
        error_payloads=["'", "\"", "')", "';", "\\"], error_signatures=_SQL_ERRORS,
        boolean_pairs=[("' OR '1'='1' -- -", "' AND '1'='2' -- -"),
                       (" OR 1=1-- -", " AND 1=2-- -")],
        time_payloads=["' AND SLEEP(5)-- -", "'||pg_sleep(5)-- -",
                       "';WAITFOR DELAY '0:0:5'-- -", " OR SLEEP(5)-- -"]),
    "ssti": Pack(
        "ssti", "Server-side template injection probe", "WSTG-INPV-18", ["eval"],
        eval_payloads=_SSTI),
    "xpath": Pack(
        "xpath", "XPath injection probe", "WSTG-INPV-09", ["error", "boolean"],
        error_payloads=["'", "\"", "']", "')", "' and '1'='1"], error_signatures=_XPATH_ERRORS,
        boolean_pairs=[("' or '1'='1", "' or '1'='2"), (" or 1=1", " or 1=2")]),
    "ldap": Pack(
        "ldap", "LDAP injection probe", "WSTG-INPV-06", ["error", "boolean"],
        error_payloads=[")", "(", "*)(", ")(cn=*", "\\"], error_signatures=_LDAP_ERRORS,
        # A wildcard matches everything (page like the baseline); a non-existent value does not.
        boolean_pairs=[("*", "ZZnoSuchValueZZ")]),
    "cmd": Pack(
        "cmd", "OS command injection probe (time-based)", "WSTG-INPV-12", ["time"],
        time_payloads=["; sleep 5", "| sleep 5", "& sleep 5", "$(sleep 5)", "`sleep 5`",
                       "; ping -c 5 127.0.0.1", "& timeout /t 5"]),
    "ssi": Pack(
        "ssi", "Server-side includes probe", "WSTG-INPV-08", ["ssi"],
        ssi_directive='<!--#echo var="DATE_GMT"-->'),
    "crlf": Pack(
        "crlf", "HTTP response splitting probe (CRLF)", "WSTG-INPV-15", ["crlf"], crlf=True),
}


# ---- request gathering -------------------------------------------------------------

def gather(base: str, katana: Path | None, har: Path | None) -> list[Req]:
    """Candidate requests: the har requests forge finds (state-changing and parameterised
    GET), plus every parameterised GET from the crawl, deduplicated and capped."""
    reqs = list(gather_requests(base, har))
    seen = {(r.method, r.template, tuple(sorted(r.names))) for r in reqs}
    sp = urlsplit(base)
    origin = f"{sp.scheme}://{sp.netloc}"
    cands, states = reflmod.candidates(base, katana, har)
    cookie, _ = reflmod._cookie_for(states, sp.scheme, (sp.hostname or "").lower())
    for path, pairs in cands:
        key = ("GET", harmod._template(path), tuple(sorted(n for n, _ in pairs)))
        if key in seen:
            continue
        seen.add(key)
        reqs.append(Req("GET", f"{origin}{path}?{urlencode(pairs, quote_via=quote)}",
                        cookie=cookie, query=list(pairs)))
    return reqs


def _targets(reqs: list[Req]) -> list[tuple[Req, str]]:
    """(request, parameter) pairs to probe: each named parameter of each request once."""
    out, seen = [], set()
    for r in reqs:
        for name in r.names:
            key = (r.method, r.template, name)
            if key not in seen:
                seen.add(key)
                out.append((r, name))
    return out


# ---- sending -----------------------------------------------------------------------

def inject_one(r: Req, name: str, suffix: str) -> ep.Answer:
    """Resend r with `suffix` appended to the current value of parameter `name`, keeping
    every other parameter, so the page stays the real screen."""
    in_body = any(n == name for n, _ in r.body_params)
    query, body_params = list(r.query), list(r.body_params)
    if in_body:
        cur = next(v for n, v in body_params if n == name)
        body_params, _ = _set(body_params, name, cur + suffix)
    else:
        cur = next((v for n, v in query if n == name), "")
        query, _ = _set(query, name, cur + suffix)
    return _send(r, query, body_params, r.body_text, r.is_json)


def _timed(r: Req, name: str, suffix: str) -> tuple[ep.Answer, float]:
    t = time.monotonic()
    a = inject_one(r, name, suffix)
    return a, time.monotonic() - t


# ---- classifiers -------------------------------------------------------------------

def _new_signature(baseline: str, body: str, signatures: list[str]) -> str:
    """The first error signature present in `body` but not in `baseline` (or "")."""
    for rx in signatures:
        if re.search(rx, body or "", re.I) and not re.search(rx, baseline or "", re.I):
            return rx
    return ""


def _similar(a: ep.Answer, b: ep.Answer) -> bool:
    """Roughly the same page: same status and body length within 5%."""
    if a.status != b.status:
        return False
    la, lb = len(a.body or ""), len(b.body or "")
    return abs(la - lb) <= max(32, 0.05 * max(la, lb, 1))


@dataclass
class Finding:
    request: Req
    name: str
    verdict: str           # SUSPECTED-<kind> | clean | error (no answer)
    detail: str
    sent: int = 0


def probe(r: Req, name: str, pack: Pack, pause: float = 0, should_stop=lambda: False) -> Finding:
    base = inject_one(r, name, "")
    sent = 1
    if base.status is None:
        return Finding(r, name, "no answer", base.error, sent)

    def wait():
        if pause:
            time.sleep(pause)

    if "error" in pack.checks:
        for p in pack.error_payloads:
            if should_stop():
                break
            wait()
            a = inject_one(r, name, p)
            sent += 1
            hit = _new_signature(base.body, a.body, pack.error_signatures)
            if hit:
                return Finding(r, name, "SUSPECTED-error", f"{p!r} -> engine error ({hit})", sent)

    if "eval" in pack.checks:
        for payload, marker in pack.eval_payloads:
            if should_stop():
                break
            wait()
            a = inject_one(r, name, payload)
            sent += 1
            if marker in (a.body or "") and marker not in (base.body or "") and payload not in (a.body or ""):
                return Finding(r, name, "SUSPECTED-eval", f"{payload!r} evaluated to {marker}", sent)

    if "boolean" in pack.checks:
        for ptrue, pfalse in pack.boolean_pairs:
            if should_stop():
                break
            wait()
            at = inject_one(r, name, ptrue)
            sent += 1
            wait()
            af = inject_one(r, name, pfalse)
            sent += 1
            if at.status is None or af.status is None:
                continue
            lt, lf = len(at.body or ""), len(af.body or "")
            # TRUE keeps the page (like the baseline), FALSE clearly shrinks or changes it.
            if _similar(at, base) and not _similar(af, base) and (lf <= lt * (1 - BODY_SHRINK) or af.status != at.status):
                return Finding(r, name, "SUSPECTED-boolean",
                               f"TRUE {ptrue!r} ~ baseline, FALSE {pfalse!r} changed "
                               f"(len {lt} vs {lf}, status {at.status}/{af.status})", sent)

    if "ssi" in pack.checks and pack.ssi_directive:
        token = "WSTGSSI" + secrets.token_hex(3)
        a = inject_one(r, name, f"{pack.ssi_directive}{token}")
        sent += 1
        body = a.body or ""
        # The marker reflects (so the value reached the output) but the directive did not
        # come back verbatim: it was interpreted (or stripped) server-side.
        if token in body and token not in (base.body or "") and pack.ssi_directive not in body \
                and "<!--#echo" not in body:
            return Finding(r, name, "SUSPECTED-ssi",
                           f"{pack.ssi_directive!r} was consumed server-side while the marker reflected", sent)

    if "crlf" in pack.checks and pack.crlf:
        token = "wstg" + secrets.token_hex(3)
        a = inject_one(r, name, f"\r\nX-Wstg-Inject: {token}")
        sent += 1
        if a.status is not None and any(token in (n or "") or token in (v or "") for n, v in a.headers):
            return Finding(r, name, "SUSPECTED-crlf",
                           f"CRLF payload injected a response header carrying {token}", sent)

    if "time" in pack.checks:
        t0 = min(_timed(r, name, "")[1] for _ in range(2))
        sent += 2
        for p in pack.time_payloads:
            if should_stop():
                break
            wait()
            a, dt = _timed(r, name, p)
            sent += 1
            if a.status is not None and dt >= t0 + TIME_MARGIN:
                wait()
                a2, dt2 = _timed(r, name, p)      # confirm: a one-off slow response is not a hit
                sent += 1
                if dt2 >= t0 + TIME_MARGIN:
                    return Finding(r, name, "SUSPECTED-time",
                                   f"{p!r} took {dt:.1f}s and {dt2:.1f}s vs baseline {t0:.1f}s", sent)

    return Finding(r, name, "clean", "no injection signal from the standard payloads", sent)


# ---- CLI ---------------------------------------------------------------------------

def run(args) -> int:
    pack = PACKS.get(args.pack)
    if not pack:
        print(f"unknown pack {args.pack!r}; one of {', '.join(PACKS)}", file=sys.stderr)
        return 2
    base = args.base.rstrip("/")
    host = (urlsplit(base).hostname or "").lower()
    reqs = gather(base, Path(args.katana) if args.katana else None,
                  Path(args.har) if args.har else None)
    pairs = _targets(reqs)
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        pairs = [(r, n) for r, n in pairs if n in wanted]
    over = max(0, len(pairs) - args.max)
    pairs = pairs[:args.max]

    print(f"# {pack.title} ({pack.wstg}) on {host}; standard payloads only, no bypass "
          "fuzzing; reuses the captured session, contacts only this host")
    print(f"# {len(pairs)} parameter(s) to probe"
          + (f", {over} over the limit of {args.max} (skipped)" if over else "")
          + f"; checks: {', '.join(pack.checks)}")

    if args.list:
        for i, (r, n) in enumerate(pairs, 1):
            print(f"{i}\t{r.method}\t{r.template}\t?{n}\t(role {r.role or 'anonymous'})")
        if not pairs:
            print("(no parameter found: collect katana-crawl, or capture har-browse)")
        return 0

    chosen = set(range(1, len(pairs) + 1)) if args.all else set(args.request)
    if not chosen:
        print("give --request N (repeatable) or --all (see --list)", file=sys.stderr)
        return 2
    if any(not 1 <= n <= len(pairs) for n in chosen):
        print(f"--request out of range 1..{len(pairs)} (run --list)", file=sys.stderr)
        return 2
    if not args.agree:
        print("this sends active injection payloads (a WAF may flag them); pass --agree", file=sys.stderr)
        return 2

    stop = Path(args.stop_file) if args.stop_file else None

    def should_stop():
        return bool(stop and stop.is_file())

    suspected = answered = 0
    for pos, n in enumerate(sorted(chosen), 1):
        if should_stop():
            print(f"\n# stopped: {pos - 1}/{len(chosen)} done.", flush=True)
            break
        r, name = pairs[n - 1]
        if pos > 1 and args.pause:
            time.sleep(args.pause)
        f = probe(r, name, pack, pause=args.pause, should_stop=should_stop)
        print(f"\n[{pos}/{len(chosen)}] #{n} {r.method} {r.template} ?{name} (role {r.role or 'anonymous'})",
              flush=True)
        if f.verdict == "no answer":
            print(f"    no answer ({f.detail}); {f.sent} request(s)", flush=True)
            continue
        answered += 1
        if f.verdict.startswith("SUSPECTED"):
            suspected += 1
            print(f"    => {f.verdict}: {f.detail} [{f.sent} requests]", flush=True)
        else:
            print(f"    => clean: {f.detail} [{f.sent} requests]", flush=True)
    if chosen and not answered:
        print(f"no request to {host} got an answer; collect again", file=sys.stderr)
        return 4
    print(f"\n# verdict: {suspected} parameter(s) SUSPECTED by {pack.key}. The {pack.wstg} judge "
          "confirms with the evidence; a standard-payload probe is not a scanner.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-inject", description=__doc__.split("\n\n")[0])
    ap.add_argument("--pack", required=True, help=f"payload pack: {', '.join(PACKS)}")
    ap.add_argument("--base", required=True, help="base URL of the target (the only host contacted)")
    ap.add_argument("--katana", help="katana-crawl evidence version folder (optional)")
    ap.add_argument("--har", help="har-browse evidence version folder (optional)")
    ap.add_argument("--list", action="store_true", help="list the candidate parameters, send nothing")
    ap.add_argument("--request", type=int, action="append", default=[], metavar="N",
                    help="1-based parameter to probe (repeatable; see --list)")
    ap.add_argument("--all", action="store_true", help="probe every candidate parameter")
    ap.add_argument("--only", help="comma-separated parameter names to keep")
    ap.add_argument("--max", type=int, default=MAX_PARAMS, help="parameters to probe at most")
    ap.add_argument("--pause", type=float, default=0, help="seconds between requests")
    ap.add_argument("--stop-file", help="stop gracefully as soon as this file exists")
    ap.add_argument("--agree", action="store_true", help="confirm the owner agreed (sends active payloads)")
    return run(ap.parse_args(argv))
