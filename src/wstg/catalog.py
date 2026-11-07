"""WSTG catalog: test index, evidence definitions, and per-WSTG scenarios.

Layout (YAML, in the repository, English):

    catalog/wstg_index.yaml        every WSTG v4.2 test (summary, target types, OWASP page)
    catalog/evidence/*.yaml        evidence definitions, list under `evidence:`
    catalog/wstg/WSTG-*.yaml       one scenario per test (overview, criteria, steps)
    catalog/tools.yaml             tools the commands need, and how to install them

Evidence is defined once and referenced by ID from scenario steps, so several
tests share the same collected evidence. Scenario steps have a summary and any of
`command` (shown to the tester), `operation`, `evidence`, `load_note`, and:

    auto_run: true   the tool runs the command itself and shows its output (only
                     local analysis of collected evidence; see analysis.check)
    ai_task: text    the step is judged by the AI review; the text goes into the
                     AI prompt as the task for that step

`load()` parses and validates
everything; `CatalogError` lists every problem found, not just the first.

Placeholders in commands and text, filled in per target:

    {domain}    the domain target (for an FQDN target: its parent domain)
    {fqdn}      the FQDN target (web server host name)
    {base_url}  https://{fqdn} by default (scheme and port from the scope record)
    {port}      the port of {base_url} (443 by default)
    {out}       evidence commands only: the version folder the command writes files into
    {ev:ID}     step commands only: the latest version folder of evidence ID (manual
                evidence keeps its files under {ev:ID}/items/, for example items/*.har)

Proxy (WSTG_HTTP_PROXY): commands get http_proxy/https_proxy in their
environment. Tools that ignore it declare `proxy_args`, which replace the
argv element "{proxy_args}" when a proxy is set and are dropped otherwise:

    {proxy_url}       the proxy URL, for example http://proxy.example.com:3128
    {proxy_hostport}  host:port of the proxy

Pause (WSTG_PAUSE, seconds between requests, to spare weak targets): tools
with a delay option declare `pause_args`, which replace "{pause_args}" the
same way when WSTG_PAUSE is set: {pause} is the number of seconds.

`incomplete_if` lists regular expressions; when stdout or stderr matches, the
tool stopped early (for example nikto -maxtime) and the collection is failed,
never complete.

Only these names are replaced (by regular expression, not str.format), so other
braces pass through unchanged: curl globs such as {a,b} and curl's own
--write-out syntax %{http_code}. An unknown {word} is reported as an error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import PACKAGE_DIR

CATALOG_DIR = PACKAGE_DIR.parent.parent / "catalog"
OWASP_BASE = "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/"

TARGET_TYPES = ("domain", "fqdn")
EVIDENCE_KINDS = ("auto", "manual")
LEVELS = ("light", "full")
PLACEHOLDERS = {
    "domain": {"domain", "out"},
    "fqdn": {"domain", "fqdn", "base_url", "port", "out"},
}
ID_RE = re.compile(r"WSTG-[A-Z]{4}-\d{2}")
EVIDENCE_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
# "%{name}" is curl --write-out syntax, not a placeholder.
PLACEHOLDER_RE = re.compile(r"(?<!%)\{([a-z_]+)\}")
EV_REF_RE = re.compile(r"\{ev:([a-z0-9-]+)\}")
PROXY_ARGS = "{proxy_args}"
PROXY_PLACEHOLDERS = {"proxy_url", "proxy_hostport"}
PAUSE_ARGS = "{pause_args}"
PAUSE_PLACEHOLDERS = {"pause"}
OPTIONAL_ARGS = {PROXY_ARGS: ("proxy_args", PROXY_PLACEHOLDERS), PAUSE_ARGS: ("pause_args", PAUSE_PLACEHOLDERS)}
MAX_TIMEOUT = 4 * 3600
TOOL_INSTALLS = ("apt", "npm", "none")


class CatalogError(Exception):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("catalog has %d problem(s):\n  %s" % (len(problems), "\n  ".join(problems)))


@dataclass(frozen=True)
class Test:
    id: str
    category: str
    category_name: str
    title: str
    summary: str
    target_types: tuple[str, ...]
    owasp_path: str
    merged_into: str | None = None

    @property
    def owasp_url(self) -> str:
        return OWASP_BASE + self.owasp_path


@dataclass(frozen=True)
class Evidence:
    id: str
    title: str
    target_type: str
    kind: str
    description: str = ""
    level: str | None = None          # auto only: light | full
    passive: bool = False             # auto only: no traffic to the target itself
    heavy: bool = False               # slow, noisy, or lockout-prone (full only)
    argv: tuple[str, ...] = ()        # auto only; no shell
    files: tuple[str, ...] = ()       # extra files the command writes under {out}
    timeout: int = 120
    ok_exit_codes: tuple[int, ...] = (0,)  # exit codes that mean "finished"
    proxy_args: tuple[str, ...] = ()  # replace "{proxy_args}" in argv when a proxy is set
    direct: bool = False              # the tool cannot use a proxy (needs direct connections)
    pause_args: tuple[str, ...] = ()  # replace "{pause_args}" in argv when WSTG_PAUSE is set
    incomplete_if: tuple[str, ...] = ()  # regexes on stdout/stderr meaning "stopped early"
    load_note: str = ""
    source: str = ""                  # file it was defined in


@dataclass(frozen=True)
class Tool:
    name: str
    install: str = "apt"
    package: str = ""
    path: str = ""
    note: str = ""


@dataclass(frozen=True)
class Step:
    summary: str
    command: str = ""                 # command line for the tester (display)
    operation: str = ""               # concrete UI operation
    evidence: tuple[str, ...] = ()
    load_note: str = ""
    ai_task: str = ""                 # judged by the AI review: instruction added to the AI prompt
    auto_run: bool = False            # the tool runs the command itself (local analysis only)


@dataclass(frozen=True)
class Scenario:
    id: str
    overview: str
    pass_criteria: str
    fail_criteria: str
    steps: tuple[Step, ...]
    notes: tuple[str, ...] = ()
    finding_kinds: tuple[str, ...] = ()


@dataclass(frozen=True)
class FindingKind:
    id: str
    title: str
    subject: str


@dataclass
class Catalog:
    wstg_version: str
    tests: dict[str, Test]
    evidence: dict[str, Evidence]
    scenarios: dict[str, Scenario] = field(default_factory=dict)
    tools: dict[str, Tool] = field(default_factory=dict)
    finding_kinds: dict[str, FindingKind] = field(default_factory=dict)

    def evidence_for(self, test_id: str) -> list[Evidence]:
        """Evidence the scenario of a test uses, in step order, without duplicates."""
        sc = self.scenarios.get(test_id)
        if not sc:
            return []
        seen: dict[str, Evidence] = {}
        for st in sc.steps:
            for eid in st.evidence:
                seen.setdefault(eid, self.evidence[eid])
        return list(seen.values())

    def tests_using(self, evidence_id: str) -> list[str]:
        return [tid for tid, sc in self.scenarios.items()
                if any(evidence_id in st.evidence for st in sc.steps)]


# --------------------------------------------------------------------------
# Loading


def _read_yaml(path: Path, problems: list[str]):
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        problems.append(f"{path.name}: cannot read: {e}")
        return None


def _keys(where: str, d: dict, allowed: set[str], required: set[str], problems: list[str]) -> bool:
    if not isinstance(d, dict):
        problems.append(f"{where}: expected a mapping")
        return False
    for k in sorted(set(d) - allowed):
        problems.append(f"{where}: unknown key '{k}'")
    missing = sorted(required - set(d))
    for k in missing:
        problems.append(f"{where}: missing key '{k}'")
    return not missing


def _str(v) -> str:
    return "" if v is None else str(v).strip()


def _strs(v) -> tuple[str, ...]:
    if v is None:
        return ()
    if isinstance(v, str):
        return (v,)
    return tuple(str(x) for x in v)


def _load_index(path: Path, problems: list[str]) -> tuple[str, dict[str, Test]]:
    data = _read_yaml(path, problems) or {}
    tests: dict[str, Test] = {}
    for i, t in enumerate(data.get("tests") or []):
        where = f"{path.name}[{i}]"
        if not _keys(where, t, {"id", "category", "category_name", "title", "summary",
                                 "target_types", "owasp_path", "merged_into"},
                     {"id", "category", "category_name", "title", "summary", "target_types", "owasp_path"},
                     problems):
            continue
        tid = _str(t["id"])
        if not ID_RE.fullmatch(tid):
            problems.append(f"{where}: bad id '{tid}'")
        if tid in tests:
            problems.append(f"{where}: duplicate id {tid}")
        tt = _strs(t["target_types"])
        for x in tt:
            if x not in TARGET_TYPES:
                problems.append(f"{tid}: unknown target type '{x}'")
        if not tt:
            problems.append(f"{tid}: target_types is empty")
        tests[tid] = Test(id=tid, category=_str(t["category"]), category_name=_str(t["category_name"]),
                          title=_str(t["title"]), summary=_str(t["summary"]), target_types=tt,
                          owasp_path=_str(t["owasp_path"]), merged_into=_str(t.get("merged_into")) or None)
    for t in tests.values():
        if t.merged_into and t.merged_into not in tests:
            problems.append(f"{t.id}: merged_into {t.merged_into} is not in the index")
    return _str(data.get("wstg_version")), tests


EVIDENCE_KEYS = {"id", "title", "target_type", "kind", "description", "level", "passive", "heavy",
                 "argv", "files", "timeout", "ok_exit_codes", "load_note",
                 "proxy_args", "direct", "pause_args", "incomplete_if"}


def _load_evidence(dir_: Path, problems: list[str]) -> dict[str, Evidence]:
    out: dict[str, Evidence] = {}
    for path in sorted(dir_.glob("*.yaml")):
        data = _read_yaml(path, problems) or {}
        for i, e in enumerate(data.get("evidence") or []):
            where = f"evidence/{path.name}[{i}]"
            if not _keys(where, e, EVIDENCE_KEYS, {"id", "title", "target_type", "kind"}, problems):
                continue
            eid = _str(e["id"])
            where = f"evidence {eid}"
            if not EVIDENCE_ID_RE.fullmatch(eid):
                problems.append(f"{where}: id must be lower-case words joined by '-'")
            if eid in out:
                problems.append(f"{where}: defined in both {out[eid].source} and {path.name}")
            ev = Evidence(
                id=eid, title=_str(e["title"]), target_type=_str(e["target_type"]), kind=_str(e["kind"]),
                description=_str(e.get("description")), level=_str(e.get("level")) or None,
                passive=bool(e.get("passive", False)), heavy=bool(e.get("heavy", False)),
                argv=_strs(e.get("argv")), files=_strs(e.get("files")),
                timeout=int(e.get("timeout", 120)),
                ok_exit_codes=tuple(int(x) for x in e.get("ok_exit_codes", [0])), load_note=_str(e.get("load_note")),
                proxy_args=_strs(e.get("proxy_args")), direct=bool(e.get("direct", False)),
                pause_args=_strs(e.get("pause_args")), incomplete_if=_strs(e.get("incomplete_if")), source=path.name,
            )
            _check_evidence(ev, problems)
            out[eid] = ev
    return out


def _check_evidence(ev: Evidence, problems: list[str]) -> None:
    w = f"evidence {ev.id}"
    if ev.target_type not in TARGET_TYPES:
        problems.append(f"{w}: unknown target_type '{ev.target_type}'")
        return
    if ev.kind not in EVIDENCE_KINDS:
        problems.append(f"{w}: kind must be auto or manual")
        return
    if ev.kind == "auto":
        if not ev.argv:
            problems.append(f"{w}: auto evidence needs argv")
        if ev.level not in LEVELS:
            problems.append(f"{w}: auto evidence needs level light or full")
        if ev.heavy and ev.level != "full":
            problems.append(f"{w}: heavy evidence must be level full (excluded from light mode)")
        if ev.target_type == "domain" and not ev.passive:
            problems.append(f"{w}: domain targets run passive commands only (set passive: true or change target_type)")
        if ev.heavy and not ev.load_note:
            problems.append(f"{w}: heavy evidence needs a load_note")
        if not 1 <= ev.timeout <= MAX_TIMEOUT:
            problems.append(f"{w}: timeout must be 1..{MAX_TIMEOUT} seconds")
        for token, (key, names) in OPTIONAL_ARGS.items():
            args, n = getattr(ev, key), ev.argv.count(token)
            if args and n != 1:
                problems.append(f"{w}: {key} needs exactly one \"{token}\" element in argv")
            if not args and n:
                problems.append(f"{w}: argv has \"{token}\" but no {key}")
            for a in args:
                for name in PLACEHOLDER_RE.findall(a):
                    if name not in names:
                        problems.append(f"{w}: {key} may only use {', '.join('{%s}' % x for x in sorted(names))},"
                                        f" not {{{name}}}")
        if ev.proxy_args and ev.direct:
            problems.append(f"{w}: direct and proxy_args exclude each other")
        for rx in ev.incomplete_if:
            try:
                re.compile(rx)
            except re.error as e:
                problems.append(f"{w}: incomplete_if {rx!r}: {e}")
    else:
        for k, v in (("argv", ev.argv), ("level", ev.level), ("files", ev.files),
                     ("proxy_args", ev.proxy_args), ("direct", ev.direct),
                     ("pause_args", ev.pause_args), ("incomplete_if", ev.incomplete_if),
                     ("ok_exit_codes", ev.ok_exit_codes != (0,))):
            if v:
                problems.append(f"{w}: manual evidence must not set {k}")
        if not ev.description:
            problems.append(f"{w}: manual evidence needs a description of what to capture")
    allowed = PLACEHOLDERS[ev.target_type]
    for s in ev.argv:
        if s in OPTIONAL_ARGS:
            continue
        for name in PLACEHOLDER_RE.findall(s):
            if name not in allowed:
                problems.append(f"{w}: placeholder {{{name}}} is not available for {ev.target_type} targets")
    for f in ev.files:
        if f.startswith("/") or ".." in Path(f).parts:
            problems.append(f"{w}: file '{f}' must be a relative path inside {{out}}")


SCENARIO_KEYS = {"id", "overview", "pass", "fail", "notes", "steps", "finding_kinds"}
STEP_KEYS = {"summary", "command", "operation", "evidence", "load_note", "ai_task", "auto_run"}


def _load_scenarios(dir_: Path, tests: dict[str, Test], evidence: dict[str, Evidence],
                    problems: list[str], kinds: dict[str, FindingKind] | None = None) -> dict[str, Scenario]:
    out: dict[str, Scenario] = {}
    for path in sorted(dir_.glob("*.yaml")):
        d = _read_yaml(path, problems)
        where = f"wstg/{path.name}"
        if not _keys(where, d, SCENARIO_KEYS, {"id", "overview", "pass", "fail", "steps"}, problems):
            continue
        tid = _str(d["id"])
        if path.stem != tid:
            problems.append(f"{where}: id {tid} does not match the file name")
        test = tests.get(tid)
        if not test:
            problems.append(f"{where}: {tid} is not in the index")
            continue
        if test.merged_into:
            problems.append(f"{where}: {tid} is merged into {test.merged_into}; write the scenario there")
        steps = []
        for i, s in enumerate(d.get("steps") or [], 1):
            sw = f"{tid} step {i}"
            if not _keys(sw, s, STEP_KEYS, {"summary"}, problems):
                continue
            st = Step(summary=_str(s["summary"]), command=_str(s.get("command")),
                      operation=_str(s.get("operation")), evidence=_strs(s.get("evidence")),
                      load_note=_str(s.get("load_note")), ai_task=_str(s.get("ai_task")),
                      auto_run=s.get("auto_run") is True)
            if s.get("auto_run") not in (None, True, False):
                problems.append(f"{sw}: auto_run must be true or false")
            if st.auto_run:
                from . import analysis   # analysis imports this module
                if not st.command:
                    problems.append(f"{sw}: auto_run needs a command")
                problems.extend(f"{sw}: auto_run: {p}" for p in analysis.check(st.command))
            if not (st.command or st.operation or st.evidence or st.ai_task):
                problems.append(f"{sw}: needs a command, an operation, evidence, or an AI task")
            for eid in st.evidence:
                ev = evidence.get(eid)
                if not ev:
                    problems.append(f"{sw}: unknown evidence '{eid}'")
                elif ev.target_type == "fqdn" and test.target_types == ("domain",):
                    problems.append(f"{sw}: evidence '{eid}' is for FQDN targets but {tid} runs on domain targets only")
            allowed = set().union(*(PLACEHOLDERS[t] for t in test.target_types)) - {"out"}
            for text in (st.command, st.operation):
                for name in PLACEHOLDER_RE.findall(text):
                    if name not in allowed:
                        problems.append(f"{sw}: placeholder {{{name}}} is not available here")
                for eid in EV_REF_RE.findall(text):
                    if eid not in st.evidence:
                        problems.append(f"{sw}: {{ev:{eid}}} must also be listed in the step's evidence")
                # Manual evidence keeps its files under items/ in the version folder.
                for m in re.finditer(r"\{ev:([a-z0-9-]+)\}(\S*)", text):
                    ev = evidence.get(m.group(1))
                    if ev and ev.kind == "manual" and not m.group(2).startswith("/items/"):
                        problems.append(f"{sw}: files of manual evidence {ev.id} are under {{ev:{ev.id}}}/items/")
            steps.append(st)
        if not steps:
            problems.append(f"{where}: no steps")
        fk = _strs(d.get("finding_kinds"))
        for k in fk:
            if kinds is not None and k not in kinds:
                problems.append(f"{where}: unknown finding kind '{k}' (see finding_kinds.yaml)")
        out[tid] = Scenario(id=tid, overview=_str(d["overview"]), pass_criteria=_str(d["pass"]),
                            fail_criteria=_str(d["fail"]), steps=tuple(steps), notes=_strs(d.get("notes")),
                            finding_kinds=fk)
    return out


def load(root: Path | None = None) -> Catalog:
    root = root or CATALOG_DIR
    problems: list[str] = []
    version, tests = _load_index(root / "wstg_index.yaml", problems)
    evidence = _load_evidence(root / "evidence", problems)
    kinds = _load_finding_kinds(root / "finding_kinds.yaml", problems)
    scenarios = _load_scenarios(root / "wstg", tests, evidence, problems, kinds)
    tools = _load_tools(root / "tools.yaml", problems)
    if tools is not None:
        for ev in evidence.values():
            if ev.kind == "auto" and ev.argv and ev.argv[0] not in tools:
                problems.append(f"evidence {ev.id}: tool '{ev.argv[0]}' is not listed in tools.yaml")
    if problems:
        raise CatalogError(problems)
    return Catalog(wstg_version=version, tests=tests, evidence=evidence, scenarios=scenarios,
                   tools=tools or {}, finding_kinds=kinds or {})


KIND_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def _load_finding_kinds(path: Path, problems: list[str]) -> dict[str, FindingKind] | None:
    if not path.exists():
        problems.append("finding_kinds.yaml is missing")
        return None
    data = _read_yaml(path, problems) or {}
    out: dict[str, FindingKind] = {}
    for i, k in enumerate(data.get("kinds") or []):
        where = f"finding_kinds.yaml[{i}]"
        if not _keys(where, k, {"id", "title", "subject"}, {"id", "title", "subject"}, problems):
            continue
        kind = FindingKind(id=_str(k["id"]), title=_str(k["title"]), subject=_str(k["subject"]))
        if not KIND_ID_RE.match(kind.id) or kind.id == "other":
            problems.append(f"{where}: bad id {kind.id!r}")
        if kind.id in out:
            problems.append(f"{where}: duplicate kind {kind.id}")
        out[kind.id] = kind
    return out


def _load_tools(path: Path, problems: list[str]) -> dict[str, Tool] | None:
    if not path.exists():
        problems.append("tools.yaml is missing")
        return None
    data = _read_yaml(path, problems) or {}
    out: dict[str, Tool] = {}
    for i, t in enumerate(data.get("tools") or []):
        where = f"tools.yaml[{i}]"
        if not _keys(where, t, {"name", "install", "package", "path", "note"}, {"name"}, problems):
            continue
        tool = Tool(name=_str(t["name"]), install=_str(t.get("install")) or "apt",
                    package=_str(t.get("package")) or _str(t["name"]), path=_str(t.get("path")),
                    note=_str(t.get("note")))
        if tool.install not in TOOL_INSTALLS:
            problems.append(f"{where}: install must be one of {', '.join(TOOL_INSTALLS)}")
        if tool.name in out:
            problems.append(f"{where}: duplicate tool {tool.name}")
        out[tool.name] = tool
    return out


# --------------------------------------------------------------------------
# Rendering


def render(text: str, values: dict[str, str], evidence_paths: dict[str, str] | None = None) -> str:
    """Fill in known placeholders. Unknown names and other braces stay as they are."""
    def sub(m: re.Match) -> str:
        return values.get(m.group(1), m.group(0))

    out = PLACEHOLDER_RE.sub(sub, text)
    if evidence_paths is not None:
        out = EV_REF_RE.sub(lambda m: evidence_paths.get(m.group(1), m.group(0)), out)
    return out
