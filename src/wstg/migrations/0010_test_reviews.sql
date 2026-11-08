-- Per-test tester annotations, separate from step verdicts and AI reviews:
--   no_need        the tester marked the test not applicable ("no need") for this
--                  target (for example GraphQL testing where no GraphQL is used);
--                  it overrides the computed status for display.
--   tester_review  the tester's own free-text review of the test (optional),
--                  alongside the imported AI review.
-- One row per (target, test); a row with no_need = 0 and an empty review is removed.

CREATE TABLE test_reviews (
    target_id     INTEGER NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    test_id       TEXT    NOT NULL,
    no_need       INTEGER NOT NULL DEFAULT 0 CHECK (no_need IN (0, 1)),
    tester_review TEXT    NOT NULL DEFAULT '',
    updated_at    TEXT    NOT NULL,
    updated_by    TEXT    NOT NULL,
    PRIMARY KEY (target_id, test_id)
);
