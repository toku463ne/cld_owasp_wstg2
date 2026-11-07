"""Findings created from WSTG pages.

Status is open / in progress / closed. closed_at is set when a finding is
closed and cleared when it is reopened. A finding may have a kind
(catalog/finding_kinds.yaml) and a subject; a target never has two findings
with the same (kind, normalized subject), even from different WSTG tests. The CVSS score and severity are
computed from the vector on every read (`cvss.score`), never stored.
"""

from __future__ import annotations

from . import cvss
from . import db as dbmod
from . import targets as tmod

STATUSES = ("open", "in progress", "closed")
TEXT_FIELDS = ("title", "summary", "impact", "reproduction", "cvss_rationale")
MAX_TEXT = 100_000


class FindingError(Exception):
    def __init__(self, message: str, existing: int | None = None):
        super().__init__(message)
        self.existing = existing      # id of the finding that already has this key


def normalize_subject(subject: str) -> str:
    """Lower case, single spaces, no surrounding quotes/backticks or trailing '/' '.'."""
    s = " ".join((subject or "").replace("`", " ").split()).strip().strip("'\"").lower()
    return s.rstrip("/.").strip() if len(s) > 1 else s


def find_by_key(db: dbmod.Database, target: tmod.Target, kind: str, subject: str,
                exclude: int | None = None) -> int | None:
    if not kind:
        return None
    row = db.one("SELECT id FROM findings WHERE target_id = ? AND kind = ? AND subject = ? AND id != ?",
                 (target.id, kind, normalize_subject(subject), exclude or 0))
    return row["id"] if row else None


def _decorate(row: dict | None) -> dict | None:
    if row is None:
        return None
    row["cvss"] = cvss.try_score(row["cvss_vector"])
    return row


def _clean(data: dict, kinds=None) -> dict:
    out = {}
    for k in TEXT_FIELDS:
        v = (data.get(k) or "").replace("\r\n", "\n").strip()
        if len(v) > MAX_TEXT:
            raise FindingError(f"{k} is too long")
        out[k] = v
    if not out["title"]:
        raise FindingError("a finding needs a title")
    if len(out["title"]) > 300:
        raise FindingError("the title is longer than 300 characters")
    status = data.get("status") or "open"
    if status not in STATUSES:
        raise FindingError(f"status must be one of {', '.join(STATUSES)}")
    out["status"] = status
    vector = (data.get("cvss_vector") or "").strip()
    if vector:
        try:
            vector = cvss.normalize(vector)
        except cvss.CvssError as e:
            raise FindingError(f"CVSS vector: {e}") from None
    out["cvss_vector"] = vector
    kind = (data.get("kind") or "").strip()
    if kind == "other":
        kind = ""
    subject = normalize_subject(data.get("subject") or "")
    if kind and kinds is not None and kind not in kinds:
        raise FindingError(f"unknown finding kind {kind!r}")
    if kind and not subject:
        raise FindingError("a finding with a kind needs a subject (what or where, see the kind)")
    if len(subject) > 300:
        raise FindingError("the subject is longer than 300 characters")
    out["kind"], out["subject"] = kind, subject if kind else ""
    return out


def _check_key(db, target, f: dict, exclude: int | None = None) -> None:
    if (other := find_by_key(db, target, f["kind"], f["subject"], exclude)) is not None:
        raise FindingError(f"finding {other} already covers {f['kind']}: {f['subject']}", existing=other)


def create(db: dbmod.Database, target: tmod.Target, test_id: str, data: dict, actor: str,
           kinds=None) -> int:
    """Create a finding. `kinds`: allowed kind ids (None = not checked).
    Raises FindingError(existing=id) when the target has a finding with the same key."""
    f = _clean(data, kinds)
    _check_key(db, target, f)
    now = dbmod.utcnow()
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO findings (target_id, test_id, title, status, summary, impact, reproduction,"
            " cvss_vector, cvss_rationale, created_at, created_by, updated_at, updated_by, closed_at,"
            " kind, subject) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (target.id, test_id, f["title"], f["status"], f["summary"], f["impact"], f["reproduction"],
             f["cvss_vector"], f["cvss_rationale"], now, actor, now, actor,
             now if f["status"] == "closed" else None, f["kind"], f["subject"]))
        db.audit(conn, actor, "finding.create", target=target.name, finding=cur.lastrowid, test=test_id)
        return cur.lastrowid


def update(db: dbmod.Database, target: tmod.Target, finding_id: int, data: dict, actor: str,
           kinds=None) -> None:
    old = get(db, target, finding_id)
    if not old:
        raise FindingError("no such finding")
    f = _clean(data, kinds)
    _check_key(db, target, f, exclude=finding_id)
    changed = [k for k in (*TEXT_FIELDS, "status", "cvss_vector", "kind", "subject") if f[k] != old[k]]
    if not changed:
        return
    now = dbmod.utcnow()
    closed_at = old["closed_at"]
    if f["status"] == "closed" and old["status"] != "closed":
        closed_at = now
    elif f["status"] != "closed":
        closed_at = None
    with db.tx() as conn:
        conn.execute(
            "UPDATE findings SET title=?, status=?, summary=?, impact=?, reproduction=?, cvss_vector=?,"
            " cvss_rationale=?, updated_at=?, updated_by=?, closed_at=?, kind=?, subject=?"
            " WHERE id=? AND target_id=?",
            (f["title"], f["status"], f["summary"], f["impact"], f["reproduction"], f["cvss_vector"],
             f["cvss_rationale"], now, actor, closed_at, f["kind"], f["subject"], finding_id, target.id))
        db.audit(conn, actor, "finding.update", target=target.name, finding=finding_id, fields=changed,
                 before={k: old[k] for k in changed})


def get(db: dbmod.Database, target: tmod.Target, finding_id: int) -> dict | None:
    return _decorate(db.one("SELECT * FROM findings WHERE id = ? AND target_id = ?", (finding_id, target.id)))


def list_for(db: dbmod.Database, target: tmod.Target, test_id: str | None = None) -> list[dict]:
    sql, args = "SELECT * FROM findings WHERE target_id = ?", [target.id]
    if test_id:
        sql += " AND test_id = ?"
        args.append(test_id)
    rows = [_decorate(r) for r in db.query(sql + " ORDER BY id", args)]
    # Highest score first, unrated after rated, then newest update first.
    rows.sort(key=lambda r: r["updated_at"], reverse=True)
    rows.sort(key=lambda r: -(r["cvss"]["score"] if r["cvss"] else -1))
    return rows
