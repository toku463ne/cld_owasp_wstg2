-- Test targets, their scope records, and per-step verdicts.

CREATE TABLE targets (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,           -- lower-case host name: example.com, www.example.com
    type        TEXT    NOT NULL CHECK (type IN ('domain', 'fqdn')),
    parent_id   INTEGER REFERENCES targets (id),   -- FQDN -> its domain target
    description TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL,
    created_by  TEXT    NOT NULL,
    CHECK (type = 'fqdn' OR parent_id IS NULL)
);

-- One scope record per target. Every command is checked against it before it runs.
CREATE TABLE scopes (
    target_id         INTEGER PRIMARY KEY REFERENCES targets (id) ON DELETE CASCADE,
    allowed_hosts     TEXT NOT NULL DEFAULT '',     -- one per line; "*.example.com" matches subdomains
    allowed_ports     TEXT NOT NULL DEFAULT '',     -- comma-separated, e.g. "80,443"
    base_url          TEXT NOT NULL DEFAULT '',     -- FQDN targets: https://www.example.com[:port]
    authorization_ref TEXT NOT NULL DEFAULT '',     -- contract / approval reference
    valid_from        TEXT,                         -- YYYY-MM-DD, inclusive
    valid_until       TEXT,                         -- YYYY-MM-DD, inclusive
    updated_at        TEXT NOT NULL,
    updated_by        TEXT NOT NULL
);

-- Verdict of one step of one WSTG scenario. No row = "-" (not judged).
-- step is the 1-based position of the step in catalog/wstg/<test_id>.yaml.
CREATE TABLE step_verdicts (
    target_id  INTEGER NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    test_id    TEXT    NOT NULL,
    step       INTEGER NOT NULL,
    verdict    TEXT    NOT NULL CHECK (verdict IN ('pass', 'fail')),
    updated_at TEXT    NOT NULL,
    updated_by TEXT    NOT NULL,
    PRIMARY KEY (target_id, test_id, step)
);
