-- Findings. Severity is computed from cvss_vector; it is never stored.

CREATE TABLE findings (
    id             INTEGER PRIMARY KEY,
    target_id      INTEGER NOT NULL REFERENCES targets (id),
    test_id        TEXT    NOT NULL,                 -- WSTG test the finding was created from
    title          TEXT    NOT NULL,
    status         TEXT    NOT NULL CHECK (status IN ('open', 'in progress', 'closed')),
    summary        TEXT    NOT NULL DEFAULT '',
    impact         TEXT    NOT NULL DEFAULT '',
    reproduction   TEXT    NOT NULL DEFAULT '',
    cvss_vector    TEXT    NOT NULL DEFAULT '',      -- CVSS:3.1/AV:../..; empty = not rated yet
    cvss_rationale TEXT    NOT NULL DEFAULT '',
    created_at     TEXT    NOT NULL,
    created_by     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    updated_by     TEXT    NOT NULL,
    closed_at      TEXT                              -- set when status becomes closed
);

CREATE INDEX findings_target ON findings (target_id, test_id);
