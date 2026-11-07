-- Duplicate check for findings: a kind (catalog/finding_kinds.yaml) and a
-- normalized subject. A target has at most one finding per (kind, subject),
-- whichever WSTG test it comes from. Empty kind = no key (checked by title only).
ALTER TABLE findings ADD COLUMN kind TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN subject TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX findings_key ON findings (target_id, kind, subject) WHERE kind != '';
