-- rotation key lengths (#580, client-core plan §7 P4).
--
-- A rotation row holds the predecessor's and the candidate's raw public keys.
-- They were always 32-byte Ed25519 keys (20261105020356). An iPhone rotates
-- one Secure Enclave P-256 key to another, so a key may now also be a 65-byte
-- uncompressed point (`04 || X || Y`).
--
-- The row names no algorithm: both keys are compared byte for byte with
-- `remote_certificates.public_key`, whose `key_algorithm` ties each length to
-- one algorithm (20261124213330), so equal bytes mean the same key of the same
-- algorithm. A rotation never changes an identity's algorithm, so when both
-- keys are present they have the same length.
--
-- SQLite cannot change a CHECK in place, so the table is rebuilt. No other
-- table, trigger or view names `remote_identity_rotation`, so the rename needs
-- no `legacy_alter_table`. Its schedule index is recreated unchanged.
CREATE TABLE remote_identity_rotation_v2 (
    host_id BLOB PRIMARY KEY REFERENCES remote_hosts(id) ON DELETE CASCADE
        CHECK(length(host_id) = 16),
    sequence INTEGER NOT NULL DEFAULT 0 CHECK(sequence >= 0),
    last_completed_at INTEGER NOT NULL CHECK(last_completed_at >= 0),
    phase TEXT NOT NULL DEFAULT 'complete'
        CHECK(phase IN ('complete', 'challenged', 'issued', 'committed')),
    operation_id BLOB UNIQUE CHECK(operation_id IS NULL OR length(operation_id) = 16),
    challenge BLOB CHECK(challenge IS NULL OR length(challenge) = 32),
    predecessor_fingerprint BLOB
        CHECK(predecessor_fingerprint IS NULL OR length(predecessor_fingerprint) = 32),
    predecessor_public_key BLOB
        CHECK(predecessor_public_key IS NULL OR length(predecessor_public_key) = 32
            OR (length(predecessor_public_key) = 65 AND substr(predecessor_public_key, 1, 1) = X'04')),
    issuer_fingerprint BLOB
        CHECK(issuer_fingerprint IS NULL OR length(issuer_fingerprint) = 32),
    issuer_generation INTEGER CHECK(issuer_generation IS NULL OR issuer_generation > 0),
    started_at INTEGER CHECK(started_at IS NULL OR started_at >= 0),
    csr_digest BLOB CHECK(csr_digest IS NULL OR length(csr_digest) = 32),
    candidate_public_key BLOB
        CHECK(candidate_public_key IS NULL OR length(candidate_public_key) = 32
            OR (length(candidate_public_key) = 65 AND substr(candidate_public_key, 1, 1) = X'04')),
    candidate_fingerprint BLOB
        CHECK(candidate_fingerprint IS NULL OR length(candidate_fingerprint) = 32),
    candidate_certificate BLOB
        CHECK(candidate_certificate IS NULL OR length(candidate_certificate) BETWEEN 1 AND 8192),
    candidate_attempted_at INTEGER CHECK(candidate_attempted_at IS NULL OR candidate_attempted_at >= 0),
    CHECK(predecessor_public_key IS NULL OR candidate_public_key IS NULL
        OR length(predecessor_public_key) = length(candidate_public_key))
);

INSERT INTO remote_identity_rotation_v2 (
    host_id, sequence, last_completed_at, phase, operation_id, challenge,
    predecessor_fingerprint, predecessor_public_key, issuer_fingerprint,
    issuer_generation, started_at, csr_digest, candidate_public_key,
    candidate_fingerprint, candidate_certificate, candidate_attempted_at
)
SELECT host_id, sequence, last_completed_at, phase, operation_id, challenge,
    predecessor_fingerprint, predecessor_public_key, issuer_fingerprint,
    issuer_generation, started_at, csr_digest, candidate_public_key,
    candidate_fingerprint, candidate_certificate, candidate_attempted_at
FROM remote_identity_rotation;

DROP TABLE remote_identity_rotation;
ALTER TABLE remote_identity_rotation_v2 RENAME TO remote_identity_rotation;

CREATE INDEX remote_identity_rotation_schedule
    ON remote_identity_rotation(phase, last_completed_at, host_id);
