-- Persist one challenged public identity transition per enrolled host [285].
CREATE TABLE remote_identity_rotation (
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
        CHECK(predecessor_public_key IS NULL OR length(predecessor_public_key) = 32),
    issuer_fingerprint BLOB
        CHECK(issuer_fingerprint IS NULL OR length(issuer_fingerprint) = 32),
    issuer_generation INTEGER CHECK(issuer_generation IS NULL OR issuer_generation > 0),
    started_at INTEGER CHECK(started_at IS NULL OR started_at >= 0),
    csr_digest BLOB CHECK(csr_digest IS NULL OR length(csr_digest) = 32),
    candidate_public_key BLOB
        CHECK(candidate_public_key IS NULL OR length(candidate_public_key) = 32),
    candidate_fingerprint BLOB
        CHECK(candidate_fingerprint IS NULL OR length(candidate_fingerprint) = 32),
    candidate_certificate BLOB
        CHECK(candidate_certificate IS NULL OR length(candidate_certificate) BETWEEN 1 AND 8192),
    candidate_attempted_at INTEGER CHECK(candidate_attempted_at IS NULL OR candidate_attempted_at >= 0)
);

CREATE INDEX remote_identity_rotation_schedule
    ON remote_identity_rotation(phase, last_completed_at, host_id);
