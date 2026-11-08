-- Allow a "no need" step verdict: a step that does not apply to this target
-- (for example a PoC confirmation that is not required once the analysis is
-- clear). It counts as a completed step that is not expected to pass, so an
-- overall pass/fail can be computed without that step being marked "pass".
-- SQLite cannot alter a CHECK constraint in place, so rebuild the table.
-- Nothing references step_verdicts, so dropping and recreating it is safe.
CREATE TABLE step_verdicts_new (
    target_id  INTEGER NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    test_id    TEXT    NOT NULL,
    step       INTEGER NOT NULL,
    verdict    TEXT    NOT NULL CHECK (verdict IN ('pass', 'fail', 'no need')),
    updated_at TEXT    NOT NULL,
    updated_by TEXT    NOT NULL,
    PRIMARY KEY (target_id, test_id, step)
);
INSERT INTO step_verdicts_new (target_id, test_id, step, verdict, updated_at, updated_by)
    SELECT target_id, test_id, step, verdict, updated_at, updated_by FROM step_verdicts;
DROP TABLE step_verdicts;
ALTER TABLE step_verdicts_new RENAME TO step_verdicts;
