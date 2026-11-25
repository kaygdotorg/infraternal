-- identity key algorithm (#580, client-core plan §7 P2).
--
-- A certificate's public key was always a raw 32-byte Ed25519 key (0015). An
-- iPhone's identity key lives in the Secure Enclave, which holds only P-256
-- keys, so a certificate now records its key's algorithm:
--
-- - `key_algorithm = 'ed25519'`: the raw 32-byte key, exactly as before. Every
--   existing row becomes this, and it is the default, so every existing writer
--   keeps working unchanged.
-- - `key_algorithm = 'p256'`: the 65-byte uncompressed SEC1 point (`04 || X || Y`).
--
-- A writer that stores a P-256 key without naming its algorithm fails the
-- check below instead of being recorded as Ed25519: forgetting it fails closed.
-- Which identities may hold a P-256 key is policy in the server, not here.
--
-- SQLite cannot change a CHECK in place, so the table is rebuilt. No other
-- table, trigger or view names `remote_certificates`, and nothing references it
-- by foreign key, so the rename needs no `legacy_alter_table`. Its own index and
-- its two triggers (20261109081612) go with the old table and are recreated
-- unchanged.
CREATE TABLE remote_certificates_v2 (
    fingerprint BLOB PRIMARY KEY NOT NULL CHECK (length(fingerprint) = 32),
    host_id BLOB NOT NULL REFERENCES remote_hosts(id) ON DELETE RESTRICT,
    issuer_fingerprint BLOB NOT NULL CHECK (length(issuer_fingerprint) = 32),
    public_key BLOB NOT NULL,
    not_before BIGINT NOT NULL CHECK (not_before >= 0),
    not_after BIGINT NOT NULL CHECK (not_after > not_before AND not_after - not_before = 604800),
    revoked_at BIGINT CHECK (revoked_at >= 0),
    role TEXT NOT NULL DEFAULT 'active' CHECK (role IN ('active', 'successor')),
    execution_uid BIGINT CHECK (execution_uid IS NULL OR execution_uid BETWEEN 0 AND 4294967295),
    key_algorithm TEXT NOT NULL DEFAULT 'ed25519' CHECK (key_algorithm IN ('ed25519', 'p256')),
    CHECK (
        (key_algorithm = 'ed25519' AND length(public_key) = 32)
        OR (key_algorithm = 'p256' AND length(public_key) = 65 AND substr(public_key, 1, 1) = X'04')
    )
);

INSERT INTO remote_certificates_v2 (
    fingerprint, host_id, issuer_fingerprint, public_key, not_before, not_after,
    revoked_at, role, execution_uid, key_algorithm
)
SELECT fingerprint, host_id, issuer_fingerprint, public_key, not_before, not_after,
    revoked_at, role, execution_uid, 'ed25519'
FROM remote_certificates;

DROP TABLE remote_certificates;
ALTER TABLE remote_certificates_v2 RENAME TO remote_certificates;

CREATE INDEX remote_certificates_host ON remote_certificates(host_id, not_after);

-- Unchanged from 20261109081612: a successor is always root (D376).
CREATE TRIGGER remote_certificates_successor_is_root_insert
BEFORE INSERT ON remote_certificates
WHEN NEW.role = 'successor' AND NEW.execution_uid IS NOT 0
BEGIN
    SELECT RAISE(ABORT, 'a successor certificate is for uid 0');
END;

-- Unchanged from 20261109081612: a role changes only successor→active, and the uid never.
CREATE TRIGGER remote_certificates_role_write_once
BEFORE UPDATE OF role, execution_uid ON remote_certificates
WHEN NEW.execution_uid IS NOT OLD.execution_uid
    OR (NEW.role IS NOT OLD.role AND NOT (OLD.role = 'successor' AND NEW.role = 'active'))
BEGIN
    SELECT RAISE(ABORT, 'certificate role and uid are write-once');
END;

-- New: a certificate's key and its algorithm are facts of the signed DER, so
-- they never change. No writer updates them; this makes that an invariant.
CREATE TRIGGER remote_certificates_key_write_once
BEFORE UPDATE OF public_key, key_algorithm ON remote_certificates
WHEN NEW.public_key IS NOT OLD.public_key OR NEW.key_algorithm IS NOT OLD.key_algorithm
BEGIN
    SELECT RAISE(ABORT, 'certificate key and algorithm are write-once');
END;
