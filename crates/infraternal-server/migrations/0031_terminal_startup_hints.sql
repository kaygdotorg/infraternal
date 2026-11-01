-- D315: switches control hints, never login behavior. A first-use claim is per account and host.
CREATE TABLE terminal_startup_hints (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    enabled INTEGER CHECK(enabled IN (0,1)),
    shown INTEGER NOT NULL DEFAULT 0 CHECK(shown IN (0,1)),
    PRIMARY KEY(user_id,host)
);
