"""Run the analysis command of a scenario step automatically (`auto_run: true`).

Analysis commands read collected evidence only (grep, jq, openssl x509 on files...),
so the tool runs them itself instead of the tester copying them into a shell. The
output is shown under the step and goes into the AI prompt.

Safety: `check()` (used by `wstg catalog-check`) allows only commands whose every
program is in LOCAL_TOOLS, so an auto-run command never sends traffic to the
target or anywhere else. Commands run with bash in a fresh temporary folder, with
a small environment (no proxy variables), a timeout, and an output cap.

Results are cached per target in `<evidence>/<target>/.analysis/<key>.json`; the
key covers the rendered command and the version of every evidence it reads, so a
new evidence version runs the command again.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import catalog as catmod
from . import db as dbmod

TIMEOUT = 30
MAX_OUTPUT = 256 * 1024

# Programs that only read and transform local files.
LOCAL_TOOLS = {
    "grep", "jq", "sed", "awk", "sort", "uniq", "tr", "cut", "cat", "head", "tail", "wc",
    "comm", "perl", "find", "printf", "echo", "tee", "base64", "xxd", "cd", "true", "test",
    "openssl",   # x509 only, see below
}
SHELL_WORDS = {"{", "}", "!"}
PUNCT = set("|&;()<>")
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def check(command: str) -> list[str]:
    """Problems that keep `command` from running automatically."""
    try:
        lex = shlex.shlex(command.replace("$(", " $( ").replace("\n", " ; "), posix=True,
                          punctuation_chars="|&;()<>")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError as e:
        return [f"cannot parse the command: {e}"]
    problems, expect, after_redirect = [], True, False
    for i, tok in enumerate(tokens):
        if tok == "$":
            continue
        if set(tok) <= PUNCT:
            if set(tok) & set("|&;("):
                expect, after_redirect = True, False
            elif set(tok) & set("<>"):
                after_redirect = True
            continue
        if after_redirect:
            after_redirect = False
            continue
        if not expect:
            continue
        if tok in SHELL_WORDS or ASSIGN_RE.match(tok):
            continue
        expect = False
        name = tok.rsplit("/", 1)[-1]
        if name not in LOCAL_TOOLS:
            problems.append(f"'{tok}' is not a local tool (allowed: {', '.join(sorted(LOCAL_TOOLS))})")
        elif name == "openssl" and (i + 1 >= len(tokens) or tokens[i + 1] != "x509"):
            problems.append("openssl may run only as 'openssl x509' (reads a file)")
    if not catmod.EV_REF_RE.search(command):
        problems.append("reads no evidence ({ev:ID})")
    return problems


@dataclass
class Result:
    status: str              # ok | missing | error
    output: str = ""
    exit_code: int | None = None
    ran_at: str = ""
    versions: dict | None = None
    note: str = ""


def _versions(command: str, ev_paths: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """{evidence id: version folder name} for every {ev:ID}, and the ids not collected."""
    found, missing = {}, []
    for eid in dict.fromkeys(catmod.EV_REF_RE.findall(command)):
        p = ev_paths.get(eid)
        link = Path(p) if p else None
        if link and link.is_symlink() and (link.parent / os.readlink(link)).is_dir():
            found[eid] = os.readlink(link)
        else:
            missing.append(eid)
    return found, missing


def run(cache_dir: Path, raw_command: str, rendered: str, ev_paths: dict[str, str]) -> Result:
    """Run (or read from the cache) the rendered command of one step."""
    versions, missing = _versions(raw_command, ev_paths)
    if missing:
        return Result("missing", note="not run: evidence not collected: " + ", ".join(missing))
    key = hashlib.sha256(json.dumps([rendered, versions], sort_keys=True).encode()).hexdigest()[:32]
    cached = cache_dir / f"{key}.json"
    if cached.is_file():
        try:
            d = json.loads(cached.read_text())
            return Result(d["status"], d["output"], d.get("exit_code"), d["ran_at"], d["versions"], d.get("note", ""))
        except (ValueError, KeyError):
            pass
    cache_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".run-", dir=cache_dir))
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LANG": "C.UTF-8",
           "HOME": str(work)}
    status, note, code = "ok", "", None
    try:
        with open(work / ".out", "wb") as out:
            proc = subprocess.Popen(["bash", "-c", rendered], cwd=work, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=subprocess.STDOUT, env=env, start_new_session=True)
            try:
                code = proc.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, 9)
                proc.wait()
                status, note = "error", f"timed out after {TIMEOUT} s"
        data = (work / ".out").read_bytes()
    except OSError as e:
        data, status, note = b"", "error", f"cannot run: {e}"
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if len(data) > MAX_OUTPUT:
        data, note = data[:MAX_OUTPUT], (note + "; " if note else "") + f"output cut at {MAX_OUTPUT} bytes"
    res = Result(status, data.decode(errors="replace"), code, dbmod.utcnow(), versions, note)
    if status == "ok":   # a timeout or error is tried again next time
        tmp = cached.with_suffix(".tmp")
        tmp.write_text(json.dumps(res.__dict__))
        tmp.replace(cached)
    return res
