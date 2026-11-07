-- AI reviews imported on a WSTG page: the pasted answer, the parsed review,
-- and what was done with each proposed step verdict.

CREATE TABLE ai_reviews (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    test_id    TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    created_by TEXT    NOT NULL,
    answer     TEXT    NOT NULL,      -- the AI answer as pasted
    review     TEXT    NOT NULL,      -- parsed review (JSON)
    results    TEXT    NOT NULL       -- per-step outcome (JSON)
);

CREATE INDEX ai_reviews_test ON ai_reviews (target_id, test_id, id);
