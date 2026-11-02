-- Preferred names belong to a person, never a browser or numeric host uid [229][231].
CREATE TABLE preferred_accounts (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    account TEXT NOT NULL CHECK(length(account) BETWEEN 1 AND 32)
);
-- Empty host denotes the embedded host. Remote ids are authenticated before write;
-- tombstoned host preferences remain inert rather than becoming another host's default.
CREATE TABLE preferred_host_accounts (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host_id BLOB NOT NULL CHECK(length(host_id) IN (0,16)),
    account TEXT NOT NULL CHECK(length(account) BETWEEN 1 AND 32),
    PRIMARY KEY(user_id,host_id)
);
