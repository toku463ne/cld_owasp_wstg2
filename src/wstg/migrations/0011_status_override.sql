-- Generalise the per-test "no need" flag into a full tester status override:
-- the tester can set the WSTG status directly to any value, or leave it empty
-- ('' = auto, i.e. computed from the step verdicts). The old no_need flag becomes
-- a 'no need' override. no_need is kept (written 0 from now on) so the 0010 CHECK
-- still holds; status_override is authoritative.

ALTER TABLE test_reviews ADD COLUMN status_override TEXT NOT NULL DEFAULT ''
    CHECK (status_override IN ('', 'started', 'pass', 'fail', 'no need'));

UPDATE test_reviews SET status_override = 'no need', no_need = 0 WHERE no_need = 1;
