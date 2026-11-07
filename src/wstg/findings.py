"""Findings created from WSTG pages.

Status is open / in progress / closed. closed_at is set when a finding is
closed and cleared when it is reopened. The CVSS score and severity are
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
    pass


def _decorate(row: dict | None) -> dict | None:
    if row is None:
        return None
    row["cvss"] = cvss.try_score(row["cvss_vector"])
    return row


def _clean(data: dict) -> dict:
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
    return out


def create(db: dbmod.Database, target: tmod.Target, test_id: str, data: dict, actor: str) -> int:
    f = _clean(data)
    now = dbmod.utcnow()
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO findings (target_id, test_id, title, status, summary, impact, reproduction,"
            " cvss_vector, cvss_rationale, created_at, created_by, updated_at, updated_by, closed_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (target.id, test_id, f["title"], f["status"], f["summary"], f["impact"], f["reproduction"],
             f["cvss_vector"], f["cvss_rationale"], now, actor, now, actor,
             now if f["status"] == "closed" else None))
        db.audit(conn, actor, "finding.create", target=target.name, finding=cur.lastrowid, test=test_id)
        return cur.lastrowid


def update(db: dbmod.Database, target: tmod.Target, finding_id: int, data: dict, actor: str) -> None:
    old = get(db, target, finding_id)
    if not old:
        raise FindingError("no such finding")
    f = _clean(data)
    changed = [k for k in (*TEXT_FIELDS, "status", "cvss_vector") if f[k] != old[k]]
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
            " cvss_rationale=?, updated_at=?, updated_by=?, closed_at=? WHERE id=? AND target_id=?",
            (f["title"], f["status"], f["summary"], f["impact"], f["reproduction"], f["cvss_vector"],
             f["cvss_rationale"], now, actor, closed_at, finding_id, target.id))
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
