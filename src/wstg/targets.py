"""Test targets (domain / FQDN), scope records, scope checks, and WSTG status.

A domain target (example.com) is tested with passive commands only. An FQDN
target (www.example.com) is a web server; it normally has a parent domain
target and can read that domain's evidence.

Every command is checked against the target's scope record before it runs
(`check_command`): the record must name an authorization, be inside its
validity period, and allow every host and port the command would contact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

from . import db as dbmod
from .config import Config

TYPES = ("domain", "fqdn")
VERDICTS = ("pass", "fail")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class TargetError(Exception):
    pass


class ScopeError(Exception):
    """A command is outside the target's scope record; it must not run."""


# --------------------------------------------------------------------------
# Names


def normalize_name(name: str) -> str:
    name = (name or "").strip().lower().rstrip(".")
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(_LABEL_RE.fullmatch(x) for x in labels):
        raise TargetError(f"not a valid host name: {name!r} (letters, digits, '-', at least one dot)")
    if labels[-1].isdigit():
        raise TargetError("IP addresses are not targets; use a host name")
    return name


def host_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower().rstrip("."), pattern.strip().lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return host == pattern


# --------------------------------------------------------------------------
# Records


@dataclass(frozen=True)
class Target:
    id: int
    name: str
    type: str
    parent_id: int | None
    parent_name: str | None
    description: str
    created_at: str

    @property
    def domain(self) -> str | None:
        """The domain this target belongs to: itself, or its parent domain."""
        return self.name if self.type == "domain" else self.parent_name


@dataclass(frozen=True)
class Scope:
    allowed_hosts: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    base_url: str
    authorization_ref: str
    valid_from: str | None
    valid_until: str | None
    updated_at: str
    updated_by: str

    @property
    def base_port(self) -> int:
        u = urlsplit(self.base_url)
        return u.port or (443 if u.scheme == "https" else 80)


_TARGET_SQL = """SELECT t.id, t.name, t.type, t.parent_id, p.name AS parent_name, t.description, t.created_at
                 FROM targets t LEFT JOIN targets p ON p.id = t.parent_id"""


def _target(row: dict | None) -> Target | None:
    return Target(**row) if row else None


def list_all(db: dbmod.Database) -> list[Target]:
    """Domains first, each followed by its FQDNs; FQDNs without a parent last."""
    rows = [Target(**r) for r in db.query(_TARGET_SQL + " ORDER BY t.name")]
    out = []
    for d in (r for r in rows if r.type == "domain"):
        out.append(d)
        out.extend(r for r in rows if r.parent_id == d.id)
    out.extend(r for r in rows if r.type == "fqdn" and r.parent_id is None)
    return out


def get(db: dbmod.Database, name: str) -> Target | None:
    return _target(db.one(_TARGET_SQL + " WHERE t.name = ?", (name,)))


def evidence_dir(cfg: Config, target: Target | str) -> Path:
    name = target.name if isinstance(target, Target) else target
    p = (cfg.evidence_root / name).resolve()
    if p.parent != cfg.evidence_root.resolve():
        raise TargetError(f"evidence folder of {name!r} escapes the evidence root")
    return p


def create(db: dbmod.Database, cfg: Config, name: str, type_: str, parent: str | None = None,
           description: str = "", actor: str = "-") -> Target:
    name = normalize_name(name)
    if type_ not in TYPES:
        raise TargetError(f"type must be one of {', '.join(TYPES)}")
    parent_t = None
    if parent:
        if type_ != "fqdn":
            raise TargetError("only an FQDN target has a parent domain")
        parent_t = get(db, normalize_name(parent))
        if not parent_t or parent_t.type != "domain":
            raise TargetError(f"parent domain target not found: {parent}")
        if not name.endswith("." + parent_t.name):
            raise TargetError(f"{name} is not under the domain {parent_t.name}")
    if get(db, name):
        raise TargetError(f"target already exists: {name}")
    now = dbmod.utcnow()
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO targets (name, type, parent_id, description, created_at, created_by) VALUES (?,?,?,?,?,?)",
            (name, type_, parent_t.id if parent_t else None, description.strip(), now, actor))
        # Default scope: the target host only, the standard web ports. Not valid
        # for active commands until an authorization reference and dates are set.
        conn.execute(
            "INSERT INTO scopes (target_id, allowed_hosts, allowed_ports, base_url, updated_at, updated_by)"
            " VALUES (?,?,?,?,?,?)",
            (cur.lastrowid, name, "80,443" if type_ == "fqdn" else "",
             f"https://{name}" if type_ == "fqdn" else "", now, actor))
        db.audit(conn, actor, "target.create", target=name, type=type_, parent=parent_t.name if parent_t else None)
    evidence_dir(cfg, name).mkdir(mode=0o700, exist_ok=True)
    return get(db, name)


def update_description(db: dbmod.Database, target: Target, description: str, actor: str) -> None:
    with db.tx() as conn:
        conn.execute("UPDATE targets SET description = ? WHERE id = ?", (description.strip(), target.id))
        db.audit(conn, actor, "target.update", target=target.name)


# --------------------------------------------------------------------------
# Scope


def get_scope(db: dbmod.Database, target: Target) -> Scope:
    r = db.one("SELECT * FROM scopes WHERE target_id = ?", (target.id,))
    if not r:
        raise TargetError(f"{target.name} has no scope record")
    return Scope(
        allowed_hosts=tuple(h for h in r["allowed_hosts"].split() if h),
        allowed_ports=tuple(int(p) for p in r["allowed_ports"].replace(" ", "").split(",") if p),
        base_url=r["base_url"], authorization_ref=r["authorization_ref"],
        valid_from=r["valid_from"], valid_until=r["valid_until"],
        updated_at=r["updated_at"], updated_by=r["updated_by"])


def _parse_date(value: str, label: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    if not _DATE_RE.fullmatch(value):
        raise TargetError(f"{label} must be YYYY-MM-DD")
    try:
        date.fromisoformat(value)
    except ValueError:
        raise TargetError(f"{label} is not a valid date") from None
    return value


def update_scope(db: dbmod.Database, target: Target, *, allowed_hosts: str, allowed_ports: str,
                 base_url: str, authorization_ref: str, valid_from: str, valid_until: str,
                 actor: str) -> None:
    hosts = []
    for h in allowed_hosts.replace(",", " ").split():
        wild = h.startswith("*.")
        hosts.append(("*." if wild else "") + normalize_name(h[2:] if wild else h))
    ports = []
    for p in allowed_ports.replace(" ", "").split(","):
        if not p:
            continue
        if not p.isdigit() or not 1 <= int(p) <= 65535:
            raise TargetError(f"bad port: {p}")
        ports.append(int(p))
    base_url = base_url.strip().rstrip("/")
    if target.type == "fqdn":
        u = urlsplit(base_url)
        if u.scheme not in ("http", "https") or not u.hostname or u.path or u.query:
            raise TargetError("base URL must look like https://host or https://host:port")
        if u.hostname != target.name:
            raise TargetError(f"base URL host must be {target.name}")
    elif base_url:
        raise TargetError("a domain target has no base URL")
    vf, vu = _parse_date(valid_from, "valid from"), _parse_date(valid_until, "valid until")
    if vf and vu and vf > vu:
        raise TargetError("valid from is after valid until")
    with db.tx() as conn:
        conn.execute(
            "UPDATE scopes SET allowed_hosts=?, allowed_ports=?, base_url=?, authorization_ref=?,"
            " valid_from=?, valid_until=?, updated_at=?, updated_by=? WHERE target_id=?",
            ("\n".join(hosts), ",".join(map(str, sorted(set(ports)))), base_url,
             authorization_ref.strip(), vf, vu, dbmod.utcnow(), actor, target.id))
        db.audit(conn, actor, "scope.update", target=target.name, hosts=hosts, ports=sorted(set(ports)),
                 base_url=base_url, authorization_ref=authorization_ref.strip(), valid_from=vf, valid_until=vu)


def scope_problems(scope: Scope, today: date | None = None) -> list[str]:
    """Why the scope record does not allow running commands now (empty = allowed)."""
    today = today or date.today()
    out = []
    if not scope.authorization_ref:
        out.append("no authorization reference")
    if not scope.valid_from or not scope.valid_until:
        out.append("no validity period")
    else:
        if today < date.fromisoformat(scope.valid_from):
            out.append(f"not valid before {scope.valid_from}")
        if today > date.fromisoformat(scope.valid_until):
            out.append(f"expired on {scope.valid_until}")
    return out


_URL_RE = re.compile(r"\b(https?)://([A-Za-z0-9.-]+)(?::(\d+))?")
_HOSTPORT_RE = re.compile(r"^([A-Za-z0-9.-]+\.[A-Za-z]{2,}):(\d+)$")
_BARE_HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$")


# Flags whose value is request content (a header), never a host to connect to.
# A URL or host inside such a value must not be read as a contacted host: curl -H
# "Origin: https://evil.example" connects to the request URL, not to evil.example.
_HEADER_FLAGS = {"-H", "--header"}


def contacted(argv: list[str], target: Target) -> list[tuple[str, int | None]]:
    """Hosts (and ports, when known) a rendered command line would contact."""
    out = []
    skip_next = False
    for a in argv:
        if skip_next:
            skip_next = False
            continue
        if a in _HEADER_FLAGS:
            skip_next = True
            continue
        for scheme, host, port in _URL_RE.findall(a):
            out.append((host.lower(), int(port) if port else (443 if scheme == "https" else 80)))
        m = _HOSTPORT_RE.match(a)
        if m:
            out.append((m.group(1).lower(), int(m.group(2))))
        elif _BARE_HOST_RE.match(a):
            # A bare argument that looks like a host name is treated as a host the
            # command contacts (fail closed: a file name like "out.json" is refused
            # unless it is in the scope; write such files as {out}/name instead).
            out.append((a.lower().rstrip("."), None))
    return out


def check_command(target: Target, scope: Scope, argv: list[str], *, passive: bool,
                  today: date | None = None) -> None:
    """Raise ScopeError unless the command may run for this target now.

    Passive commands (DNS, WHOIS, CT logs, archives) contact third parties only;
    they need an authorization and a valid period but no host match. Domain
    targets run passive commands only.
    """
    problems = scope_problems(scope, today)
    if problems:
        raise ScopeError(f"{target.name}: scope record does not allow commands ({'; '.join(problems)})")
    if passive:
        return
    if target.type == "domain":
        raise ScopeError(f"{target.name} is a domain target: passive commands only")
    hosts = contacted(argv, target)
    if not hosts:
        raise ScopeError("cannot tell which host the command contacts; refusing")
    for host, port in hosts:
        if not any(host_matches(host, p) for p in scope.allowed_hosts):
            raise ScopeError(f"host {host} is not in the scope of {target.name}")
        if port is not None and port not in scope.allowed_ports:
            raise ScopeError(f"port {port} on {host} is not in the scope of {target.name}")


# --------------------------------------------------------------------------
# Placeholders


def placeholder_values(cfg: Config, target: Target, scope: Scope) -> dict[str, str]:
    v = {"domain": target.domain or "{domain}"}
    if target.type == "fqdn":
        v.update(fqdn=target.name, base_url=scope.base_url or f"https://{target.name}",
                 port=str(scope.base_port))
    return v


def evidence_owner(target: Target, evidence_target_type: str) -> str | None:
    """Which target's folder holds evidence of a given target type."""
    if evidence_target_type == target.type:
        return target.name
    if evidence_target_type == "domain" and target.type == "fqdn":
        return target.parent_name
    return None


# --------------------------------------------------------------------------
# Verdicts and status


def verdicts(db: dbmod.Database, target: Target, test_id: str | None = None) -> dict:
    """{test_id: {step: verdict}} for the target (or one test)."""
    sql = "SELECT test_id, step, verdict FROM step_verdicts WHERE target_id = ?"
    args: tuple = (target.id,)
    if test_id:
        sql += " AND test_id = ?"
        args += (test_id,)
    out: dict[str, dict[int, str]] = {}
    for r in db.query(sql, args):
        out.setdefault(r["test_id"], {})[r["step"]] = r["verdict"]
    return out


def set_verdict(db: dbmod.Database, target: Target, test_id: str, step: int, verdict: str | None,
                actor: str) -> None:
    """Set a step verdict; None (or "-") resets the step."""
    if verdict in (None, "", "-"):
        with db.tx() as conn:
            conn.execute("DELETE FROM step_verdicts WHERE target_id=? AND test_id=? AND step=?",
                         (target.id, test_id, step))
            db.audit(conn, actor, "verdict.reset", target=target.name, test=test_id, step=step)
        return
    if verdict not in VERDICTS:
        raise TargetError(f"verdict must be one of -, {', '.join(VERDICTS)}")
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO step_verdicts (target_id, test_id, step, verdict, updated_at, updated_by)"
            " VALUES (?,?,?,?,?,?) ON CONFLICT (target_id, test_id, step) DO UPDATE SET"
            " verdict=excluded.verdict, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
            (target.id, test_id, step, verdict, dbmod.utcnow(), actor))
        db.audit(conn, actor, "verdict.set", target=target.name, test=test_id, step=step, verdict=verdict)


def status(step_count: int, step_verdicts: dict[int, str], has_evidence: bool = False) -> str:
    """WSTG status: '-', 'started', 'pass', 'fail'.

    fail if any step failed; pass only if every step passed; started if
    anything was judged or collected; '-' otherwise. A test without a
    scenario (step_count 0) is never pass.
    """
    vs = [v for s, v in step_verdicts.items() if 1 <= s <= step_count]
    if "fail" in vs:
        return "fail"
    if step_count and len(vs) == step_count and all(v == "pass" for v in vs):
        return "pass"
    if vs or has_evidence:
        return "started"
    return "-"
