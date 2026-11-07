"""Evidence store: versioned folders per target and evidence ID.

    <evidence root>/<target>/<evidence id>/
        v0001/  meta.json, items/...     one complete version
        v0002/  ...                      every change makes a new version
        latest -> v0002                  newest complete version

A version is a full snapshot: adding, editing, or removing an item writes a
new version with the whole item set. Earlier versions are never changed;
unchanged files are hard-linked from the previous version. A version is
written to a temporary folder and renamed into place only when complete, so a
partial write is never mistaken for evidence.

Item types: image (PNG/JPEG, with a caption), file (any upload), text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import db as dbmod
from . import targets as tmod
from .config import Config

META = "meta.json"
MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 45 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_IMAGES_PER_ADD = 20
IMAGE_TYPES = {b"\x89PNG\r\n\x1a\n": (".png", "image/png"), b"\xff\xd8\xff": (".jpg", "image/jpeg")}
_VERSION_RE = re.compile(r"v(\d{4,})")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class EvidenceError(Exception):
    pass


@dataclass
class Item:
    type: str                  # image | file | text
    file: str                  # path inside the version folder
    sha256: str
    size: int
    caption: str = ""          # image caption, or a title for files and text
    name: str = ""             # original file name (uploads)
    mime: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in ("", None)}


@dataclass
class Version:
    target: str
    evidence_id: str
    version: int
    path: Path
    meta: dict
    items: list[Item] = field(default_factory=list)

    @property
    def created_at(self) -> str:
        return self.meta.get("created_at", "")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fsync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def image_type(data: bytes) -> tuple[str, str]:
    for magic, t in IMAGE_TYPES.items():
        if data.startswith(magic):
            return t
    raise EvidenceError("only PNG and JPEG images are accepted")


def safe_name(name: str) -> str:
    name = _SAFE_NAME_RE.sub("_", os.path.basename(name or "")).strip("._") or "file"
    return name[:100]


class Store:
    def __init__(self, cfg: Config, db: dbmod.Database):
        self.cfg, self.db = cfg, db

    # ---- reading ------------------------------------------------------------

    def folder(self, target: str, evidence_id: str) -> Path:
        return tmod.evidence_dir(self.cfg, target) / evidence_id

    def load(self, target: str, evidence_id: str, version: int | None = None) -> Version | None:
        """A complete version (the latest when version is None)."""
        base = self.folder(target, evidence_id)
        if version is None:
            link = base / "latest"
            if not link.is_symlink():
                return None
            m = _VERSION_RE.fullmatch(os.readlink(link))
            if not m:
                return None
            version = int(m.group(1))
        path = base / f"v{version:04d}"
        meta_path = path / META
        if not meta_path.is_file():
            return None
        meta = json.loads(meta_path.read_text())
        items = [Item(**i) for i in meta.get("items", [])]
        return Version(target, evidence_id, version, path, meta, items)

    def history(self, target: tmod.Target, evidence_id: str) -> list[dict]:
        return self.db.query(
            "SELECT * FROM evidence_versions WHERE target_id = ? AND evidence_id = ? ORDER BY version DESC",
            (target.id, evidence_id))

    def latest_rows(self, target: tmod.Target) -> dict[str, dict]:
        """{evidence_id: newest complete version row} for one target."""
        rows = self.db.query(
            "SELECT * FROM evidence_versions WHERE target_id = ? AND status = 'complete' ORDER BY version",
            (target.id,))
        return {r["evidence_id"]: r for r in rows}

    def file_path(self, version: Version, rel: str) -> Path:
        """Path of a file listed in the version's items (nothing else is served)."""
        if rel not in {i.file for i in version.items} and rel not in version.meta.get("files", {}):
            raise EvidenceError("no such file in this version")
        p = (version.path / rel).resolve()
        if version.path.resolve() not in p.parents:
            raise EvidenceError("bad path")
        return p

    # ---- writing ------------------------------------------------------------

    def _write_version(self, target: tmod.Target, evidence_id: str, *, source: str, actor: str,
                       summary: str, items: list[Item], prev: Version | None,
                       new_files: dict[str, bytes], extra_meta: dict | None = None,
                       status: str = "complete") -> Version:
        """Write a version: items are copied (hard-linked) from prev unless their
        file is in new_files. Temp folder, fsync, rename, index, then `latest`."""
        base = self.folder(target.name, evidence_id)
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = base / f".tmp-{secrets.token_hex(6)}"
        tmp.mkdir(mode=0o700)
        try:
            for it in items:
                dest = tmp / it.file
                dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if it.file in new_files:
                    dest.write_bytes(new_files[it.file])
                else:
                    if prev is None:
                        raise EvidenceError(f"no source for {it.file}")
                    src = prev.path / it.file
                    try:
                        os.link(src, dest)
                    except OSError:
                        shutil.copy2(src, dest)
                _fsync(dest)
                it.sha256, it.size = _sha256(dest), dest.stat().st_size
            for rel, data in new_files.items():
                if not (tmp / rel).exists():          # files outside items (auto: stdout.txt ...)
                    (tmp / rel).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    (tmp / rel).write_bytes(data)
                    _fsync(tmp / rel)
            now = dbmod.utcnow()
            meta = {
                "schema_version": 1, "target": target.name, "evidence_id": evidence_id,
                "source": source, "status": status, "created_at": now, "created_by": actor,
                "summary": summary, "based_on": prev.version if prev else None,
                "items": [i.to_dict() for i in items], **(extra_meta or {}),
            }
            (tmp / META).write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
            _fsync(tmp / META)
            _fsync(tmp)
            with self.db.tx() as conn:
                row = conn.execute(
                    "SELECT COALESCE(MAX(version), 0) + 1 FROM evidence_versions WHERE target_id=? AND evidence_id=?",
                    (target.id, evidence_id)).fetchone()
                version = row[0]
                final = base / f"v{version:04d}"
                if final.exists():
                    raise EvidenceError(f"{final} already exists; the index and the folder disagree")
                os.rename(tmp, final)
                try:
                    conn.execute(
                        "INSERT INTO evidence_versions (target_id, evidence_id, version, source, status,"
                        " created_at, created_by, summary, item_count) VALUES (?,?,?,?,?,?,?,?,?)",
                        (target.id, evidence_id, version, source, status, now, actor, summary, len(items)))
                    self.db.audit(conn, actor, f"evidence.{source}", target=target.name, evidence=evidence_id,
                                  version=version, status=status, summary=summary)
                except BaseException:
                    os.rename(final, tmp)   # not indexed: back to temp, removed below
                    raise
            _fsync(base)
            if status == "complete":
                link_tmp = base / f".latest-{secrets.token_hex(4)}"
                os.symlink(final.name, link_tmp)
                os.replace(link_tmp, base / "latest")
            return self.load(target.name, evidence_id, version)
        finally:
            if tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True)

    def _next_name(self, items: list[Item], ext: str) -> str:
        n = 1 + max((int(m.group(1)) for i in items if (m := re.match(r"items/(\d+)", i.file))), default=0)
        return f"items/{n:03d}{ext}"

    def _base(self, target: tmod.Target, evidence_id: str) -> tuple[Version | None, list[Item]]:
        prev = self.load(target.name, evidence_id)
        return prev, [Item(**i.to_dict()) for i in prev.items] if prev else []

    def add_images(self, target: tmod.Target, evidence_id: str, images: list[tuple[bytes, str]],
                   actor: str) -> Version:
        images = [(d, c) for d, c in images if d]
        if not images:
            raise EvidenceError("no image")
        if len(images) > MAX_IMAGES_PER_ADD:
            raise EvidenceError(f"at most {MAX_IMAGES_PER_ADD} images at a time")
        prev, items = self._base(target, evidence_id)
        new = {}
        for i, (data, caption) in enumerate(images, 1):
            if len(data) > MAX_IMAGE_BYTES:
                raise EvidenceError(f"image {i} is larger than 10 MB")
            try:
                ext, mime = image_type(data)
            except EvidenceError as e:
                raise EvidenceError(f"image {i}: {e}") from None
            name = self._next_name(items, ext)
            items.append(Item("image", name, "", 0, caption=caption.strip()[:300], mime=mime))
            new[name] = data
        return self._write_version(target, evidence_id, source="manual", actor=actor,
                                   summary=f"added {len(images)} image(s)", items=items, prev=prev, new_files=new)

    def add_file(self, target: tmod.Target, evidence_id: str, data: bytes, filename: str, caption: str,
                 actor: str) -> Version:
        if not data:
            raise EvidenceError("the file is empty")
        if len(data) > MAX_FILE_BYTES:
            raise EvidenceError("the file is larger than 45 MB")
        prev, items = self._base(target, evidence_id)
        name = safe_name(filename)
        rel = self._next_name(items, "") + "-" + name
        items.append(Item("file", rel, "", 0, caption=caption.strip()[:300], name=name))
        return self._write_version(target, evidence_id, source="manual", actor=actor,
                                   summary=f"added file {name}", items=items, prev=prev, new_files={rel: data})

    def add_text(self, target: tmod.Target, evidence_id: str, text: str, caption: str, actor: str) -> Version:
        data = text.replace("\r\n", "\n").encode()
        if not data.strip():
            raise EvidenceError("the text is empty")
        if len(data) > MAX_TEXT_BYTES:
            raise EvidenceError("the text is larger than 1 MB")
        prev, items = self._base(target, evidence_id)
        rel = self._next_name(items, ".txt")
        items.append(Item("text", rel, "", 0, caption=caption.strip()[:300], mime="text/plain"))
        return self._write_version(target, evidence_id, source="manual", actor=actor,
                                   summary="added text", items=items, prev=prev, new_files={rel: data})

    def edit_item(self, target: tmod.Target, evidence_id: str, index: int, *, caption: str | None = None,
                  text: str | None = None, actor: str) -> Version:
        """Change an item's caption, or a text item's content (as a new version)."""
        prev, items = self._base(target, evidence_id)
        if not prev or not 0 <= index < len(items):
            raise EvidenceError("no such item")
        it = items[index]
        new, what = {}, []
        if caption is not None and caption.strip() != it.caption:
            it.caption = caption.strip()[:300]
            what.append("caption")
        if text is not None:
            if it.type != "text":
                raise EvidenceError("only text items have editable content")
            data = text.replace("\r\n", "\n").encode()
            if not data.strip():
                raise EvidenceError("the text is empty")
            if len(data) > MAX_TEXT_BYTES:
                raise EvidenceError("the text is larger than 1 MB")
            if data != (prev.path / it.file).read_bytes():
                stem, ext = os.path.splitext(it.file)
                stem = re.sub(r"-e\d+$", "", stem)
                it.file = f"{stem}-e{prev.version + 1}{ext}"
                new[it.file] = data
                what.append("text")
        if not what:
            return prev
        return self._write_version(target, evidence_id, source="edit", actor=actor,
                                   summary=f"edited item {index + 1} ({', '.join(what)})",
                                   items=items, prev=prev, new_files=new)

    def remove_item(self, target: tmod.Target, evidence_id: str, index: int, actor: str) -> Version:
        prev, items = self._base(target, evidence_id)
        if not prev or not 0 <= index < len(items):
            raise EvidenceError("no such item")
        gone = items.pop(index)
        return self._write_version(target, evidence_id, source="edit", actor=actor,
                                   summary=f"removed item {index + 1} ({gone.type} {gone.caption or gone.name})",
                                   items=items, prev=prev, new_files={})
