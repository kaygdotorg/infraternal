-- Preserve ordinary 15-minute invites while supporting exact-key 10-minute machine receipts [#263].
CREATE TABLE remote_join_tokens_v2 (
    host_id BLOB PRIMARY KEY NOT NULL REFERENCES remote_hosts(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('rootless', 'rootful')),
    digest BLOB NOT NULL UNIQUE CHECK (length(digest) = 32),
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0),
    expires_at BIGINT NOT NULL CHECK (
        expires_at > issued_at AND expires_at - issued_at IN (600, 900)
    ),
    consumed_at BIGINT CHECK (consumed_at >= issued_at AND consumed_at < expires_at),
    expected_key_digest BLOB CHECK (
        expected_key_digest IS NULL OR length(expected_key_digest) = 32
    )
);

INSERT INTO remote_join_tokens_v2 (
    host_id, mode, digest, issued_at, expires_at, consumed_at, expected_key_digest
)
SELECT host_id, mode, digest, issued_at, expires_at, consumed_at, expected_key_digest
FROM remote_join_tokens;

DROP TABLE remote_join_tokens;
ALTER TABLE remote_join_tokens_v2 RENAME TO remote_join_tokens;
