-- Distinguish verified login from completed browser DEK unlock; preserve existing sessions.
ALTER TABLE sessions ADD COLUMN unlocked INTEGER NOT NULL DEFAULT 1 CHECK (unlocked IN (0,1));
