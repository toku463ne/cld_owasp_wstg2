-- Index of evidence versions. The files themselves live in
-- <evidence root>/<target>/<evidence id>/v<NNNN>/ (meta.json + files).

CREATE TABLE evidence_versions (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER NOT NULL REFERENCES targets (id),
    evidence_id TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    source      TEXT    NOT NULL CHECK (source IN ('manual', 'auto', 'edit')),
    status      TEXT    NOT NULL CHECK (status IN ('complete', 'failed')),
    created_at  TEXT    NOT NULL,
    created_by  TEXT    NOT NULL,
    summary     TEXT    NOT NULL DEFAULT '',   -- what this version changed
    item_count  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (target_id, evidence_id, version)
);

CREATE INDEX evidence_versions_target ON evidence_versions (target_id, evidence_id);
