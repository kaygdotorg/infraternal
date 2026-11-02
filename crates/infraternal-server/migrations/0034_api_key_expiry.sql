-- Bound API key inactivity and give pre-upgrade keys a full lifetime at deployment [D311, #269].
CREATE TABLE server_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    api_key_lifetime_days INTEGER NOT NULL DEFAULT 30 CHECK (api_key_lifetime_days BETWEEN 1 AND 365)
);
INSERT INTO server_settings(id) VALUES (1);
ALTER TABLE api_keys ADD COLUMN renewed_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN expires INTEGER NOT NULL DEFAULT 0;
UPDATE api_keys SET renewed_at = unixepoch(), expires = unixepoch() + 2592000;
