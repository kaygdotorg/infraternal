-- Absolute deadlines cannot grow until a successful renewal; expiry is terminal (#269).
ALTER TABLE api_keys RENAME COLUMN expires TO expires_at;
ALTER TABLE api_keys ADD COLUMN dead INTEGER NOT NULL DEFAULT 0 CHECK (dead IN (0, 1));
