-- Persist public account labels while retaining the legacy name column for old readers.
ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- Preserve simple legacy names as usernames. Duplicate or invalid labels get a stable
-- UUID-derived username; display names retain the prior label, truncated by characters.
UPDATE users AS current
SET username = CASE
        WHEN length(lower(current.name)) BETWEEN 2 AND 32
            AND lower(current.name) NOT GLOB '*[^a-z0-9_-]*'
            AND (SELECT COUNT(*) FROM users AS same WHERE lower(same.name) = lower(current.name)) = 1
            AND NOT EXISTS (
                SELECT 1 FROM users AS ids
                WHERE ids.id <> current.id
                    AND lower(current.name) = substr(replace(lower(ids.id), '-', ''), 1, 32)
            )
        THEN lower(current.name)
        ELSE substr(replace(lower(current.id), '-', ''), 1, 32)
    END,
    display_name = CASE
        WHEN length(current.name) > 64 THEN substr(current.name, 1, 64)
        ELSE current.name
    END;

CREATE UNIQUE INDEX users_username_unique ON users(username);
