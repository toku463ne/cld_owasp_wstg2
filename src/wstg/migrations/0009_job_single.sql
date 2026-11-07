-- Jobs that collect one evidence (the per-evidence Collect button). force = run it
-- even when a complete version exists (Collect again); the new version is added.
ALTER TABLE jobs ADD COLUMN evidence_id TEXT NOT NULL DEFAULT '';
ALTER TABLE jobs ADD COLUMN force INTEGER NOT NULL DEFAULT 0;
