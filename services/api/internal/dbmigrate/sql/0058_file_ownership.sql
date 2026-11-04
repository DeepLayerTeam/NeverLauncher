-- 0.22.4: persist per-file ownership without modifying any published
-- manifests or previously signed v1/v2 release JSON.
ALTER TABLE files ADD COLUMN IF NOT EXISTS ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE files ADD CONSTRAINT files_ownership_0224 CHECK (ownership IN ('','managed','required','optional','user-owned','generated'));
