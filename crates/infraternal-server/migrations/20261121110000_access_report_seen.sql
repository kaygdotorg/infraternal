-- D383: a kept access report is an Inbox item for the owner until they
-- dismiss it. `seen_at` is when they did (NULL = still waiting); a new report
-- for the same host and person replaces the row and so waits again.
ALTER TABLE remote_access_reports ADD COLUMN seen_at INTEGER;
