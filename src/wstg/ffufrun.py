"""Run ffuf in resumable chunks of the word list.

`wstg-ffuf-run --resume DIR [--chunk N] -- ffuf ARGS...`

ffuf writes its JSON output only when it finishes, so a run that is stopped part
way (timeout, cancel, a reboot) keeps nothing: with WSTG_PAUSE a big list such as
backup-ffuf runs for many hours. This wrapper splits the `-w LIST:KEYWORD` word
list into chunks of N words and runs ffuf once per chunk, with `-o` pointing at
DIR/chunk-NNNN.json. A chunk counts as done only when ffuf exits 0 and its JSON
reads back (it is written to a .part file, then renamed). The next run with the
same DIR skips the done chunks and goes on with the rest. When every chunk is done,
the results are merged into the `-o` file of ARGS (ffuf's JSON format, with the
original command line).

DIR is reused only for the same scan: a fingerprint of the word list and of the
ffuf arguments that change the results (-u, -e, -H, -mc, ...; not -o, -p, -t, -x,
-rate) is kept in DIR/key.txt, and a different fingerprint starts again from
nothing. The collection runner removes DIR after the evidence is stored complete.

Exit codes: 0 all chunks done and merged, 2 usage error, otherwise the exit code
of the ffuf run that failed (the done chunks stay for the next run).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CHUNK_RE = re.compile(r"chunk-(\d{4})\.json")
# Options whose value does not change which results come back: output, pacing, proxy.
NEUTRAL_WITH_VALUE = {"-o", "-of", "-p", "-t", "-x", "-rate", "-maxtime", "-maxtime-job"}
NEUTRAL_FLAGS = {"-s", "-noninteractive", "-v", "-c"}


class UsageError(Exception):
    pass


def _option(args: list[str], name: str) -> int:
    idx = [i for i, a in enumerate(args) if a == name]
    if len(idx) != 1 or idx[0] + 1 >= len(args):
        raise UsageError(f"ffuf arguments need exactly one {name} with a value")
    return idx[0]


def fingerprint(args: list[str], words: Path) -> str:
    kept, i = [], 0
    while i < len(args):
        a = args[i]
        if a in NEUTRAL_WITH_VALUE:
            i += 2
            continue
        if a == "-w":
            kept += [a, args[i + 1].rsplit(":", 1)[-1]]   # keyword only; the list's content is hashed below
            i += 2
            continue
        if a not in NEUTRAL_FLAGS:
            kept.append(a)
        i += 1
    h = hashlib.sha256(json.dumps(kept).encode())
    h.update(words.read_bytes())
    return h.hexdigest()


def _read_json(p: Path) -> dict | None:
    try:
        data = json.loads(p.read_text(errors="replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write_atomic(p: Path, text: str) -> None:
    part = p.with_name(p.name + ".part")
    part.write_text(text)
    os.replace(part, p)


def run(resume: Path, chunk: int, cmd: list[str]) -> int:
    if not cmd:
        raise UsageError("give the ffuf command after --")
    wi, oi = _option(cmd, "-w"), _option(cmd, "-o")
    wpath, sep, keyword = cmd[wi + 1].rpartition(":")
    if not sep:
        wpath, keyword = cmd[wi + 1], "FUZZ"
    words_file = Path(wpath)
    out = Path(cmd[oi + 1])
    if not words_file.is_file():
        print(f"word list not found: {words_file}", file=sys.stderr)
        return 2
    words = words_file.read_text(errors="replace").splitlines()
    chunks = [words[i:i + chunk] for i in range(0, len(words), chunk)] or [[]]

    resume.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = fingerprint(cmd, words_file)
    key_file = resume / "key.txt"
    if not key_file.is_file() or key_file.read_text().strip() != key:
        for p in resume.iterdir():
            if p.is_file():
                p.unlink()
            else:
                shutil.rmtree(p, ignore_errors=True)
        key_file.write_text(key + "\n")
    for p in resume.glob("*.part"):
        p.unlink()

    total = len(chunks)
    done = {i for i in range(total) if _read_json(resume / f"chunk-{i:04d}.json") is not None}
    print(f"# wstg-ffuf-run: {len(words)} words in {total} chunks of up to {chunk};"
          f" {len(done)} already done in an earlier run", flush=True)
    for i, part_words in enumerate(chunks):
        if i in done:
            continue
        wl = resume / f"words-{i:04d}.txt"
        wl.write_text("".join(w + "\n" for w in part_words))
        target = resume / f"chunk-{i:04d}.json"
        tmp = resume / f"chunk-{i:04d}.json.part"
        argv = list(cmd)
        argv[wi + 1] = f"{wl}:{keyword}"
        argv[oi + 1] = str(tmp)
        rc = subprocess.call(argv, stdin=subprocess.DEVNULL)
        data = _read_json(tmp) if rc == 0 else None
        if data is None:
            tmp.unlink(missing_ok=True)
            why = f"exit code {rc}" if rc else "no readable JSON output"
            print(f"# chunk {i + 1}/{total} failed ({why}); {len(done)} of {total} chunks are kept for the next run",
                  flush=True)
            return rc or 1
        os.replace(tmp, target)
        wl.unlink(missing_ok=True)
        done.add(i)
        print(f"# chunk {i + 1}/{total} done: {len(part_words)} words, {len(data.get('results') or [])} results",
              flush=True)

    results: list = []
    config: dict = {}
    for i in range(total):
        data = _read_json(resume / f"chunk-{i:04d}.json") or {}
        results += data.get("results") or []
        config = data.get("config") or config
    merged = {"commandline": " ".join(cmd), "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "results": results, "config": config, "chunks": total}
    _write_atomic(out, json.dumps(merged, indent=1) + "\n")
    print(f"# all {total} chunks done: {len(results)} results written to {out.name}", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wstg-ffuf-run", description=__doc__.split("\n\n")[0])
    ap.add_argument("--resume", required=True, type=Path, help="folder that keeps the done chunks between runs")
    ap.add_argument("--chunk", type=int, default=100, help="words per ffuf run (default 100)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- ffuf ARGS...")
    args = ap.parse_args(argv)
    cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
    if args.chunk < 1:
        ap.error("--chunk must be >= 1")
    try:
        return run(args.resume, args.chunk, cmd)
    except UsageError as e:
        print(f"wstg-ffuf-run: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
