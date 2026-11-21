"""CNAME checks for WSTG-CONF-10 (subdomain takeover).

`wstg-dns takeover --host H --cnames DIR --url URL` (automatic evidence
`cname-takeover` of an FQDN target): the CNAME of H from the parent domain's
subdomain-cnames folder (looked up with dig when the list is missing or does not
name H); when H has a CNAME whose target resolves, one GET of URL (the target's
base URL, the only host contacted; no redirects followed). No CNAME or a dangling
CNAME: no request. Exit 3/4 when DNS or the request failed (collect again).

CNAME of every known subdomain, from collected subdomain lists:

`wstg-dns cnames --domain D [--crtsh FILE] [--subfinder FILE] [-o FILE]` reads the
subdomains of D from the crt.sh JSON and the subfinder list (either may be missing:
it is then noted and skipped), looks up the CNAME of each name, and the A/AAAA of
each CNAME target, with `dig` in batch mode (`dig -f`). It writes one line per
subdomain:

    name -> cname-target            (the name has a CNAME)
    name -> cname-target [no address]   (the CNAME target does not resolve: dangling)
    name ->                         (no CNAME)

Only DNS lookups through the system resolver: no request goes to the hosts. The
output goes to stdout and, with -o, to a file. Exit 1 when no input could be read
(the collection then fails: an empty list is never "no dangling CNAME") and exit 3
when a lookup still fails after one retry (partial output is never complete).
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

_NAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
DIG_OPTS = ["+noall", "+answer", "+comments", "+question", "+time=3", "+tries=2"]
OK_STATUS = ("NOERROR", "NXDOMAIN")


def _names_crtsh(path: Path) -> list[str]:
    data = json.loads(path.read_text(errors="replace"))
    out = []
    for row in data if isinstance(data, list) else []:
        out += str((row or {}).get("name_value", "")).split("\n")
    return out


def _names_lines(path: Path) -> list[str]:
    return path.read_text(errors="replace").splitlines()


def collect_names(domain: str, sources: list[tuple[str, Path | None, callable]]) -> tuple[list[str], list[str]]:
    """(sorted unique subdomains of `domain`, notes about each source)."""
    domain = domain.lower().rstrip(".")
    names: set[str] = set()
    notes, used = [], 0
    for label, path, reader in sources:
        if path is None:
            continue
        if not path.is_file():
            notes.append(f"# {label}: not collected (skipped)")
            continue
        try:
            raw = reader(path)
        except (OSError, ValueError) as e:
            notes.append(f"# {label} UNAVAILABLE: cannot read {path.name} ({e.__class__.__name__}); recollect it")
            continue
        used += 1
        found = set()
        for n in raw:
            n = n.strip().lower().rstrip(".")
            if n.startswith("*."):
                n = n[2:]
            if (n == domain or n.endswith("." + domain)) and _NAME_RE.match(n):
                found.add(n)
        notes.append(f"# {label}: {len(found)} names")
        names |= found
    if not used:
        raise SystemExit("\n".join(notes + ["no subdomain source could be read; nothing looked up"]))
    return sorted(names), notes


def dig_batch(queries: list[tuple[str, str]], dig: str = "dig") -> dict[tuple[str, str], tuple[str, list]]:
    """{(name, type): (status, [(owner, type, rdata)])} for a batch of queries run with
    `dig -f`. Each answer block carries its question, so answers map to queries
    exactly; a query with no block (timeout, resolver failure) gets status "NO ANSWER"."""
    out: dict[tuple[str, str], tuple[str, list]] = {q: ("NO ANSWER", []) for q in queries}
    if not queries:
        return out
    with tempfile.TemporaryDirectory() as d:
        batch = Path(d) / "queries.txt"
        batch.write_text("".join(f"{n} {t} {' '.join(DIG_OPTS)}\n" for n, t in queries))
        proc = subprocess.run([dig, *DIG_OPTS, "-f", str(batch)], capture_output=True, text=True,
                              timeout=60 + 7 * len(queries))
    for block in re.split(r"^;; Got answer:\s*$", proc.stdout, flags=re.M)[1:]:
        q = re.search(r"^;(\S+)\s+IN\s+([A-Z]+)\s*$", block, flags=re.M)
        st = re.search(r"status: ([A-Z]+)", block)
        if not q:
            continue
        key = (q.group(1).lower().rstrip("."), q.group(2).upper())
        answers = []
        for line in block.splitlines():
            parts = line.split()
            if len(parts) >= 5 and not line.startswith(";") and parts[2] == "IN":
                answers.append((parts[0].lower().rstrip("."), parts[3].upper(), parts[4].lower().rstrip(".")))
        if key in out:
            out[key] = (st.group(1) if st else "?", answers)
    return out


def dig_retry(queries: list[tuple[str, str]], dig: str = "dig") -> dict[tuple[str, str], tuple[str, list]]:
    """dig_batch, with the queries that got no clear answer asked once more."""
    out = dig_batch(queries, dig)
    again = [q for q, (st, _) in out.items() if st not in OK_STATUS]
    if again:
        out.update(dig_batch(again, dig))
    return out


def lookup(names: list[str], dig: str = "dig") -> list[str]:
    """One output line per name (see the module docstring)."""
    cn = dig_retry([(n, "CNAME") for n in names], dig)
    cname = {}
    for n in names:
        status, answers = cn[(n, "CNAME")]
        first = next((r for o, t, r in answers if o == n and t == "CNAME"), "")
        cname[n] = (status, first)
    targets = sorted({c for _, c in cname.values() if c})
    ad = dig_retry([(t, rt) for t in targets for rt in ("A", "AAAA")], dig)
    lines = []
    for n in names:
        status, c = cname[n]
        if not c:
            lines.append(f"{n} -> " + ("" if status in OK_STATUS else f"[lookup failed: {status}]"))
            continue
        results = [ad[(c, rt)] for rt in ("A", "AAAA")]
        has_addr = any(t in ("A", "AAAA") for _, answers in results for _, t, _ in answers)
        if has_addr:
            lines.append(f"{n} -> {c}")
        elif all(st in OK_STATUS for st, _ in results):
            lines.append(f"{n} -> {c} [no address]")
        else:
            lines.append(f"{n} -> {c} [lookup failed: {'/'.join(st for st, _ in results)}]")
    return lines


def cmd_cnames(args) -> int:
    sources = [("ct-crtsh", Path(args.crtsh) if args.crtsh else None, _names_crtsh),
               ("subdomains-subfinder", Path(args.subfinder) if args.subfinder else None, _names_lines)]
    names, notes = collect_names(args.domain, sources)
    lines = notes + [f"# {len(names)} unique names of {args.domain.lower()}; DNS lookups only"]
    found = lookup(names, args.dig) if names else ["(no subdomain found)"]
    failed = sum("[lookup failed" in x for x in found)
    text = "\n".join(lines + found) + "\n"
    sys.stdout.write(text)
    if failed:
        # Partial output is never complete: the collection fails and is retried.
        print(f"{failed} of {len(names)} lookups failed (resolver timeout or SERVFAIL); collect again",
              file=sys.stderr)
        return 3
    if args.output:
        tmp = Path(args.output + ".part")
        tmp.write_text(text)
        os.replace(tmp, args.output)
    return 0


def _listed_cname(folder: Path, host: str) -> tuple[str, str] | None:
    """The `-> target [flags]` part for `host` in a subdomain-cnames version folder
    (cname-check.txt, or files uploaded by hand under items/), or None."""
    files = [folder / "cname-check.txt"] + (sorted((folder / "items").glob("*")) if (folder / "items").is_dir() else [])
    for f in files:
        if not f.is_file():
            continue
        for line in f.read_text(errors="replace").splitlines():
            m = re.match(r"^(\S+) -> ?(\S*)(.*)$", line.strip())
            if m and m.group(1).lower() == host:
                return m.group(2).lower(), m.group(3).strip()
    return None


def cmd_takeover(args) -> int:
    """Takeover probe of one target host: its CNAME from the domain's list (or looked up),
    then one GET of the target URL when the CNAME target resolves. Only `--url` is
    contacted. Exit 4 when the request gets no answer (the collection is retried)."""
    from . import takeover        # fetch() and the unclaimed-message patterns
    host = args.host.lower().rstrip(".")
    listed = _listed_cname(Path(args.cnames), host) if args.cnames else None
    if listed is not None:
        cname, flags = listed
        print(f"# CNAME of {host} from subdomain-cnames: {cname or '(none)'} {flags}".rstrip())
    else:
        why = "not collected" if not (args.cnames and Path(args.cnames).is_dir()) else "does not list it"
        line = lookup([host], args.dig)[0]
        m = re.match(r"^\S+ -> ?(\S*)(.*)$", line)
        cname, flags = m.group(1), m.group(2).strip()
        print(f"# subdomain-cnames {why}; looked up: {host} -> {cname or '(none)'} {flags}".rstrip())
        if "lookup failed" in flags:
            print(f"DNS lookup failed ({flags}); collect again", file=sys.stderr)
            return 3
    if not cname:
        print(f"{host} has no CNAME: not a takeover candidate; no request sent")
        return 0
    if "no address" in flags:
        print(f"DANGLING CNAME: {host} -> {cname} does not resolve; no request sent "
              "(a third party may be able to claim the resource)")
        return 0
    scheme = args.url.split(":", 1)[0].lower()
    proxy = os.environ.get(f"{scheme}_proxy") or os.environ.get(f"{scheme.upper()}_PROXY") or ""
    try:
        print(f"GET {args.url} (through CNAME {cname}; no redirects followed)")
        print(takeover.fetch(args.url, proxy))
    except (OSError, ValueError, http.client.HTTPException) as e:
        print(f"no answer: {getattr(e, 'reason', e)}")
        print(f"{args.url} did not answer; collect again", file=sys.stderr)
        return 4
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-dns", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("cnames", help="CNAME of every known subdomain (WSTG-CONF-10)")
    s.add_argument("--domain", required=True)
    s.add_argument("--crtsh", help="crt.sh JSON (ct-crtsh evidence)")
    s.add_argument("--subfinder", help="subfinder.txt (subdomains-subfinder evidence)")
    s.add_argument("-o", "--output", help="also write the list to this file")
    s.add_argument("--dig", default="dig", help=argparse.SUPPRESS)
    s = sub.add_parser("takeover", help="takeover probe of one target host through its CNAME (WSTG-CONF-10)")
    s.add_argument("--host", required=True, help="the target host (FQDN)")
    s.add_argument("--cnames", help="subdomain-cnames version folder of the parent domain")
    s.add_argument("--url", required=True, help="the one URL to fetch (the target's base URL)")
    s.add_argument("--dig", default="dig", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    return cmd_cnames(args) if args.cmd == "cnames" else cmd_takeover(args)


if __name__ == "__main__":
    raise SystemExit(main())
