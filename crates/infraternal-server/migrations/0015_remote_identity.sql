-- Durable remote-host authority and hashed enrollment capabilities [64][133][134], #78.
-- Tombstones outlive connections so a removed host cannot regain authority on restart.
CREATE TABLE remote_hosts (
    id BLOB PRIMARY KEY NOT NULL CHECK (length(id) = 16),
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    mode TEXT NOT NULL CHECK (mode IN ('rootless', 'rootful')),
    execution_uid BIGINT NOT NULL CHECK (execution_uid BETWEEN 0 AND 4294967295),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    revoked_at BIGINT CHECK (revoked_at >= created_at),
    CHECK (mode != 'rootful' OR execution_uid = 0),
    CHECK (mode != 'rootless' OR execution_uid != 0)
);

-- One current capability per host; replacement invalidates previous invitations.
-- No raw capability or private key is persisted. Canonical tokens hash to 32 bytes.
CREATE TABLE remote_join_tokens (
    host_id BLOB PRIMARY KEY NOT NULL REFERENCES remote_hosts(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('rootless', 'rootful')),
    digest BLOB NOT NULL UNIQUE CHECK (length(digest) = 32),
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > issued_at AND expires_at - issued_at = 900),
    consumed_at BIGINT CHECK (consumed_at >= issued_at AND consumed_at < expires_at)
);

-- Public identity ledger permits certificate and issuer overlap without key storage.
CREATE TABLE remote_certificates (
    fingerprint BLOB PRIMARY KEY NOT NULL CHECK (length(fingerprint) = 32),
    host_id BLOB NOT NULL REFERENCES remote_hosts(id) ON DELETE RESTRICT,
    issuer_fingerprint BLOB NOT NULL CHECK (length(issuer_fingerprint) = 32),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    not_before BIGINT NOT NULL CHECK (not_before >= 0),
    not_after BIGINT NOT NULL CHECK (not_after > not_before AND not_after - not_before = 604800),
    revoked_at BIGINT CHECK (revoked_at >= 0)
);

CREATE INDEX remote_certificates_host ON remote_certificates(host_id, not_after);
