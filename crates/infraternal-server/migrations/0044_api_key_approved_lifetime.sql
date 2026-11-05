-- D333: a key's lifetime is approved with its scopes. The request carries it; the key keeps it
-- as an absolute end that sliding renewal never passes. Keys from before D333 have no cap.
ALTER TABLE approvals ADD COLUMN lifetime INTEGER NOT NULL DEFAULT 86400;
ALTER TABLE api_keys ADD COLUMN hard_expires_at INTEGER;
