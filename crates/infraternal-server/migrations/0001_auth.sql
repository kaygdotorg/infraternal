-- Identity and opaque capabilities; plaintext key material never enters these tables [23–29].
CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, owner INTEGER NOT NULL CHECK(owner IN (0,1)), recovery_hash TEXT NOT NULL);
CREATE UNIQUE INDEX one_owner ON users(owner) WHERE owner = 1;
CREATE TABLE setup (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), token_hash TEXT NOT NULL, expires BIGINT NOT NULL);
CREATE TABLE passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), credential TEXT NOT NULL);
CREATE TABLE wraps (user_id TEXT NOT NULL REFERENCES users(id), kind TEXT NOT NULL, key_id TEXT NOT NULL, blob TEXT NOT NULL, PRIMARY KEY(user_id,kind,key_id));
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), device TEXT NOT NULL, expires BIGINT NOT NULL, fresh BIGINT NOT NULL);
CREATE TABLE recovery (user_id TEXT PRIMARY KEY REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE, ready BIGINT NOT NULL, expires BIGINT NOT NULL);
CREATE TABLE approvals (token_hash TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL, device TEXT NOT NULL, user_id TEXT REFERENCES users(id), expires BIGINT NOT NULL);
CREATE TABLE api_keys (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), device TEXT NOT NULL, scopes TEXT NOT NULL);
-- User-bound authorization queries must not scan other users' devices/credentials.
CREATE INDEX passkeys_user ON passkeys(user_id);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX api_keys_user ON api_keys(user_id);
CREATE INDEX approvals_user ON approvals(user_id);
CREATE INDEX approvals_expiry ON approvals(expires);
