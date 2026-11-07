-- Automatic evidence collection jobs, run by `wstg worker`.

CREATE TABLE jobs (
    id           INTEGER PRIMARY KEY,
    target_id    INTEGER NOT NULL REFERENCES targets (id),
    mode         TEXT    NOT NULL CHECK (mode IN ('light', 'full')),
    status       TEXT    NOT NULL CHECK (status IN ('queued', 'running', 'cancelling', 'done', 'cancelled', 'interrupted')),
    created_at   TEXT    NOT NULL,
    created_by   TEXT    NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    heartbeat_at TEXT,
    worker       TEXT    NOT NULL DEFAULT ''
);

-- One row per evidence the job plans to collect, in run order.
CREATE TABLE job_items (
    job_id      INTEGER NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    evidence_id TEXT    NOT NULL,
    status      TEXT    NOT NULL CHECK (status IN ('pending', 'running', 'skipped', 'complete', 'failed', 'refused', 'cancelled')),
    started_at  TEXT,
    finished_at TEXT,
    exit_code   INTEGER,
    version     INTEGER,
    message     TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (job_id, seq)
);

CREATE INDEX jobs_status ON jobs (status);
