"""Fetch the subdomains that have a CNAME and look for unclaimed-resource messages
(WSTG-CONF-10 step 3), contacting only hosts inside a scope record.

`wstg takeover-probe DOMAIN` reads the newest `subdomain-cnames` evidence of the
domain target. A subdomain is fetched only when a valid scope record (authorization
and period in force) of the domain target or of one of its FQDN targets allows the
host, and the port (443 for https, 80 for the http fallback). Every other subdomain
is listed as "skipped: out of scope" and gets no request. Subdomains whose CNAME
target has no address are not fetched either (DNS already shows they dangle).

One GET of / per host, no redirects followed (a redirect could lead out of scope),
TLS not verified, at most 600 bytes of the body kept. WSTG_HTTP_PROXY and
WSTG_PAUSE apply. The result is saved as a text file in the `takeover-responses`
evidence of the domain target (a new version; earlier runs are kept).
"""
from __future__ import annotations

import http.client
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from . import db as dbmod
from . import evidence as evmod
from . import targets as tmod
from .config import Config

CNAMES_ID = "subdomain-cnames"
EVIDENCE_ID = "takeover-responses"
BODY_BYTES = 600
TIMEOUT = 10
_LINE_RE = re.compile(r"^(\S+) -> (\S+)(.*)$")
UNCLAIMED_RE = re.compile(
    r"NoSuchBucket|The specified bucket does not exist|There isn.t a GitHub Pages site here|No such app|"
    r"herokucdn\.com/error-pages/no-such-app|404 Web Site not found|Fastly error: unknown domain|"
    r"Sorry, this shop is currently unavailable|Domain (is )?not configured|project not found|"
    r"The thing you were looking for is no longer here|Repository not found|NoSuchContainer|"
    r"The specified container does not exist", re.I)


class ProbeError(Exception):
    pass


@dataclass
class Plan:
    fetch: list[tuple[str, str, list[str]]] = field(default_factory=list)   # (host, cname, schemes)
    skipped: list[tuple[str, str, str]] = field(default_factory=list)       # (host, cname, reason)


def read_cnames(store: evmod.Store, target: tmod.Target) -> tuple[list[tuple[str, str, str]], int]:
    """([(subdomain, cname target, flags)] for names with a CNAME, evidence version)."""
    v = store.load(target.name, CNAMES_ID)
    if not v:
        raise ProbeError(f"{CNAMES_ID} of {target.name} is not collected yet; run the automatic collection first")
    files = [v.path / "cname-check.txt"] + sorted((v.path / "items").glob("*"))
    out, seen = [], set()
    for f in files:
        if not f.is_file():
            continue
        for line in f.read_text(errors="replace").splitlines():
            m = _LINE_RE.match(line.strip())
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                out.append((m.group(1).lower(), m.group(2).lower(), m.group(3).strip()))
    return out, v.version


def scopes_for(db: dbmod.Database, target: tmod.Target) -> list[tuple[str, tmod.Scope]]:
    """Valid scope records of the domain target and its FQDN targets."""
    owners = [target] + [t for t in tmod.list_all(db) if t.type == "fqdn" and t.parent_name == target.name]
    out = []
    for t in owners:
        scope = tmod.get_scope(db, t)
        if not tmod.scope_problems(scope):
            out.append((t.name, scope))
    return out


def make_plan(cnames: list[tuple[str, str, str]], scopes: list[tuple[str, tmod.Scope]]) -> Plan:
    plan = Plan()
    for host, cname, flags in cnames:
        if "no address" in flags:
            plan.skipped.append((host, cname, "CNAME target has no address (dangling in DNS; not fetched)"))
            continue
        schemes = []
        for scheme, port in (("https", 443), ("http", 80)):
            if any(any(tmod.host_matches(host, p) for p in s.allowed_hosts) and port in s.allowed_ports
                   for _, s in scopes):
                schemes.append(scheme)
        if schemes:
            plan.fetch.append((host, cname, schemes))
        else:
            plan.skipped.append((host, cname, "out of scope (no valid scope record allows this host); not fetched"))
    return plan


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url: str, proxy: str = "") -> str:
    """One GET without following redirects; a short, value-light summary of the answer."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies), _NoRedirect,
                                         urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "wstg-takeover-probe"})
    try:
        resp = opener.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:     # 3xx/4xx/5xx: the body is what we need
        resp = e
    status = getattr(resp, "status", None) or resp.code
    headers = resp.headers
    body = resp.read(BODY_BYTES).decode("utf-8", "replace")
    resp.close()
    lines = [f"status {status}; server {headers.get('Server', '-')}"]
    if headers.get("Location"):
        lines.append(f"location {headers['Location']}")
    hit = UNCLAIMED_RE.search(body)
    if hit:
        lines.append(f"UNCLAIMED-RESOURCE MESSAGE: {hit.group(0)}")
    lines.append("body: " + re.sub(r"\s+", " ", body).strip())
    return "\n".join(lines)


def probe(cfg: Config, db: dbmod.Database, store: evmod.Store, target: tmod.Target, *, actor: str,
          dry_run: bool = False, fetcher=fetch, sleep=time.sleep) -> tuple[str, Plan, evmod.Version | None]:
    if target.type != "domain":
        raise ProbeError(f"{target.name} is not a domain target (run it on the parent domain)")
    cnames, version = read_cnames(store, target)
    scopes = scopes_for(db, target)
    plan = make_plan(cnames, scopes)
    out = [f"# takeover probe of {target.name}, {dbmod.utcnow()}, from {CNAMES_ID} v{version}",
           "# scopes used: " + (", ".join(f"{n} ({', '.join(s.allowed_hosts)})" for n, s in scopes) or "none valid"),
           f"# {len(plan.fetch)} fetched, {len(plan.skipped)} skipped"]
    if dry_run:
        out += [f"would fetch {h} -> {c} ({'/'.join(s)})" for h, c, s in plan.fetch]
        out += [f"skip {h} -> {c}: {r}" for h, c, r in plan.skipped]
        return "\n".join(out) + "\n", plan, None
    for i, (host, cname, schemes) in enumerate(plan.fetch):
        if i and cfg.pause:
            sleep(cfg.pause)
        out.append(f"===== {host} -> {cname}")
        for scheme in schemes:
            try:
                out.append(f"[{scheme}] " + fetcher(f"{scheme}://{host}/", cfg.http_proxy))
                break
            except (OSError, ValueError, http.client.HTTPException) as e:   # URLError, timeouts, TLS
                out.append(f"[{scheme}] no answer: {getattr(e, 'reason', e)}")
    for host, cname, reason in plan.skipped:
        out.append(f"===== {host} -> {cname}\nskipped: {reason}")
    text = "\n".join(out) + "\n"
    stamp = dbmod.utcnow().replace(":", "").replace("-", "")
    saved = store.add_file(target, EVIDENCE_ID, text.encode(), f"takeover-{stamp}.txt",
                           f"takeover probe ({len(plan.fetch)} fetched, {len(plan.skipped)} skipped)", actor)
    return text, plan, saved
