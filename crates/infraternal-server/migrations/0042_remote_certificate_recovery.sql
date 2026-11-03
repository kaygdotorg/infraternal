-- One committed recovery result per expired predecessor makes lost replies retryable [133], #285.
-- Certificate DER is public; this table carries no host or CA private key.
CREATE TABLE remote_certificate_recovery (
    host_id BLOB NOT NULL REFERENCES remote_hosts(id) ON DELETE RESTRICT
        CHECK (length(host_id) = 16),
    predecessor_fingerprint BLOB NOT NULL
        CHECK (length(predecessor_fingerprint) = 32),
    request_id BLOB NOT NULL CHECK (length(request_id) = 32),
    csr_digest BLOB NOT NULL CHECK (length(csr_digest) = 32),
    challenge BLOB NOT NULL CHECK (length(challenge) = 32),
    public_key_fingerprint BLOB NOT NULL CHECK (length(public_key_fingerprint) = 32),
    issuer_fingerprint BLOB NOT NULL CHECK (length(issuer_fingerprint) = 32),
    issuer_generation BIGINT NOT NULL CHECK (issuer_generation > 0),
    predecessor_not_after BIGINT NOT NULL CHECK (predecessor_not_after >= 0),
    expires_at BIGINT NOT NULL CHECK (expires_at >= 0),
    certificate_fingerprint BLOB CHECK (
        certificate_fingerprint IS NULL OR length(certificate_fingerprint) = 32
    ),
    certificate_der BLOB CHECK (certificate_der IS NULL OR length(certificate_der) > 0),
    completed_at BIGINT CHECK (completed_at IS NULL OR completed_at >= 0),
    PRIMARY KEY (host_id, request_id),
    CHECK (
        (certificate_fingerprint IS NULL AND certificate_der IS NULL AND completed_at IS NULL)
        OR (certificate_fingerprint IS NOT NULL AND certificate_der IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX remote_certificate_recovery_completed_predecessor
    ON remote_certificate_recovery(host_id, predecessor_fingerprint)
    WHERE certificate_der IS NOT NULL;

CREATE INDEX remote_certificate_recovery_host_expiry
    ON remote_certificate_recovery(host_id, expires_at)
    WHERE certificate_der IS NULL;
