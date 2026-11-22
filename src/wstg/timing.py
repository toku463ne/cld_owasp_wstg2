"""Response-timing side-channel measurement (WSTG-BUSL-04 step 1, measurement half).

`wstg-timing diff --base URL --url URL --param NAME --value-a A --value-b B
                  [--fixed NAME=VALUE ...] [--method GET|POST] [--body]
                  [--har DIR] [--samples N] [--warmup N] [--pause S]`

Measures whether one request parameter's value changes the server's response time enough
to tell two states apart (for example a valid vs an unknown user name, or an existing vs
an absent record). The tester names the request, the parameter, and the two values to
compare; the tool sends the two classes interleaved (A, B, A, B, ...) so clock drift and
load trends cancel out, discards a few warm-up requests, and reports per class the median
and inter-quartile range of the round-trip time, the median response size, and the status
codes. A two-sided Mann-Whitney U test (standard library, no SciPy) says whether the two
timing distributions differ; the verdict is DISTINGUISHABLE only when the test is
significant and the median gap is above measurement noise.

This is a measurement, not an attack: GET by default (or a POST the tester chooses), only
the --base host is contacted, logged-in requests reuse the har-browse session, and the two
compared values are not printed (class A / class B, length only). The timing-window / race
(double-apply) half of WSTG-BUSL-04 stays manual - it sends concurrent state-changing
requests and its outcome is business-specific. Exit 4 when no request got an answer.
"""
from __future__ import annotations

import argparse
import math
import sys
import time
from pathlib import Path
from statistics import median
from urllib.parse import urlencode, urljoin, urlsplit

from . import entrypoints as ep
from . import har as harmod

DEFAULT_SAMPLES = 30
DEFAULT_WARMUP = 3


def _quartiles(xs: list[float]) -> tuple[float, float]:
    """(25th, 75th) percentile with linear interpolation; stable for small n."""
    s = sorted(xs)
    n = len(s)
    if n == 1:
        return s[0], s[0]

    def q(p: float) -> float:
        h = (n - 1) * p
        lo = int(math.floor(h))
        hi = min(lo + 1, n - 1)
        return s[lo] + (h - lo) * (s[hi] - s[lo])

    return q(0.25), q(0.75)


def mann_whitney_p(a: list[float], b: list[float]) -> float | None:
    """Two-sided p-value of the Mann-Whitney U test (normal approximation with tie
    correction). None when it cannot be computed (too few points or no variance)."""
    n1, n2 = len(a), len(b)
    if n1 < 3 or n2 < 3:
        return None
    combined = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    ranks = [0.0] * len(combined)
    i = 0
    ties: list[int] = []
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2 + 1          # average rank (1-based) of the tie group
        for k in range(i, j + 1):
            ranks[k] = avg
        ties.append(j - i + 1)
        i = j + 1
    r1 = sum(r for r, (_, grp) in zip(ranks, combined) if grp == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    u = min(u1, n1 * n2 - u1)
    n = n1 + n2
    tie_term = sum(t ** 3 - t for t in ties) / (n * (n - 1)) if n > 1 else 0
    var = (n1 * n2 / 12) * ((n + 1) - tie_term)
    if var <= 0:
        return None
    z = (u - n1 * n2 / 2) / math.sqrt(var)
    return math.erfc(abs(z) / math.sqrt(2))


def _mask(value: str) -> str:
    return f"{len(value)} chars"


def _build(base: str, url: str, method: str, param: str, value: str,
           fixed: list[tuple[str, str]], body: bool):
    """(url, body bytes, method, extra headers) for one request."""
    pairs = list(fixed) + [(param, value)]
    if method == "POST" and body:
        return url, urlencode(pairs).encode(), "POST", {"Content-Type": "application/x-www-form-urlencoded"}
    sp = urlsplit(url)
    existing = sp.query + "&" if sp.query else ""
    full = f"{sp.scheme}://{sp.netloc}{sp.path}?{existing}{urlencode(pairs)}"
    return full, None, method, None


def _session_cookie(base: str, har) -> str:
    sp = urlsplit(base)
    host = (sp.hostname or "").lower()
    if not har:
        return ""
    inv = ep.Inventory(base.rstrip("/") + "/")
    for role, st in ep.read_har(inv, Path(har)):
        if harmod._ANON_ROLE_RE.match(role):
            continue
        ck = ep.cookie_header(st, sp.scheme, host, "/")
        if ck:
            return ck
    return ""


def run(args) -> int:
    base = args.base.rstrip("/")
    url = urljoin(base + "/", args.url) if args.url else base + "/"
    sp, bp = urlsplit(url), urlsplit(base)
    if (sp.hostname or "").lower() != (bp.hostname or "").lower():
        print(f"--url host must be {bp.hostname} (only the base host is contacted)", file=sys.stderr)
        return 2
    method = args.method.upper()
    fixed = []
    for f in args.fixed or []:
        if "=" not in f:
            print(f"--fixed must be NAME=VALUE: {f}", file=sys.stderr)
            return 2
        n, v = f.split("=", 1)
        fixed.append((n, v))
    cookie = _session_cookie(base, args.har)

    print(f"# response-timing side-channel on {bp.hostname}: parameter '{args.param}', "
          f"class A ({_mask(args.value_a)}) vs class B ({_mask(args.value_b)})")
    print(f"# {method} {sp.path or '/'}; {args.samples} samples/class (+{args.warmup} warm-up), "
          f"interleaved; {'logged-in session (from har-browse)' if cookie else 'anonymous'}; "
          "values not shown")

    times = {"A": [], "B": []}
    sizes = {"A": [], "B": []}
    statuses = {"A": [], "B": []}
    total = args.samples + args.warmup
    for i in range(total):
        for cls, value in (("A", args.value_a), ("B", args.value_b)):
            u, data, m, extra = _build(base, url, method, args.param, value, fixed, args.body)
            if (i or cls == "B") and args.pause:
                time.sleep(args.pause)
            t0 = time.perf_counter()
            a = ep.fetch(u, cookie=cookie, extra_headers=extra, data=data, method=m)
            dt = (time.perf_counter() - t0) * 1000
            if a.status is None:
                continue
            if i >= args.warmup:                 # discard warm-up rounds
                times[cls].append(dt)
                sizes[cls].append(a.size)
                statuses[cls].append(a.status)

    if not times["A"] and not times["B"]:
        print(f"\nno request to {bp.hostname} got an answer; check the scope and the URL", file=sys.stderr)
        return 4

    for cls in ("A", "B"):
        t = times[cls]
        if not t:
            print(f"\nclass {cls}: no answer")
            continue
        q1, q3 = _quartiles(t)
        st = sorted(set(statuses[cls]))
        print(f"\nclass {cls}: n={len(t)}, median={median(t):.1f} ms, IQR={q1:.1f}-{q3:.1f} ms, "
              f"median size={int(median(sizes[cls]))} bytes, status={','.join(map(str, st))}")

    if not (times["A"] and times["B"]):
        print("\n# verdict: inconclusive (one class got no answer)")
        return 0

    med_a, med_b = median(times["A"]), median(times["B"])
    diff = med_b - med_a
    p = mann_whitney_p(times["A"], times["B"])
    noise = max(2.0, 0.10 * min(med_a, med_b))
    size_gap = abs(median(sizes["A"]) - median(sizes["B"]))
    if set(statuses["A"]) != set(statuses["B"]):
        verdict = ("STATUS-DIFFERS", "the two classes return different status codes - a direct "
                   "state oracle, independent of timing")
    elif p is not None and p < 0.01 and abs(diff) >= noise:
        note = (" (but the response sizes differ by %d bytes, so transfer time may explain part "
                "of it - confirm with equal-size responses)" % size_gap) if size_gap > 256 else ""
        verdict = ("DISTINGUISHABLE", f"median gap {diff:+.1f} ms, Mann-Whitney p={p:.4f} (< 0.01){note}")
    elif p is None:
        verdict = ("INCONCLUSIVE", "too few points or no timing variance to test")
    else:
        verdict = ("NOT-DISTINGUISHABLE", f"median gap {diff:+.1f} ms, Mann-Whitney "
                   f"p={p:.3f}; within measurement noise")
    print(f"\n# verdict: {verdict[0]} - {verdict[1]}")
    print("# the timing-window / race (double-apply) half of BUSL-04 stays manual: "
          "fire concurrent state-changing requests by hand, with the owner's agreement.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-timing", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff", help="measure a response-timing difference between two input classes")
    d.add_argument("--base", required=True, help="base URL (the only host contacted)")
    d.add_argument("--url", help="request URL or path (default: --base)")
    d.add_argument("--method", default="GET", help="GET or POST")
    d.add_argument("--param", required=True, help="the parameter toggled between the two classes")
    d.add_argument("--value-a", required=True, help="class A value")
    d.add_argument("--value-b", required=True, help="class B value")
    d.add_argument("--fixed", action="append", help="NAME=VALUE held constant (repeatable)")
    d.add_argument("--body", action="store_true", help="send parameters in the POST body (with --method POST)")
    d.add_argument("--har", help="har-browse evidence folder, to reuse a logged-in session")
    d.add_argument("--samples", type=int, default=DEFAULT_SAMPLES, help="requests per class")
    d.add_argument("--warmup", type=int, default=DEFAULT_WARMUP, help="warm-up requests per class to discard")
    d.add_argument("--pause", type=float, default=0, help="seconds between requests")
    args = ap.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
