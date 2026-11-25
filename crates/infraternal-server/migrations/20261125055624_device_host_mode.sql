-- device host mode (#580, client-core plan §7 P5; owner decision 2026-11-25).
--
-- An iPhone is stored as a third host mode, `device`, with no uid. It joins the
-- mesh, can be removed and rotates its key, but the infraternal agent never runs
-- on it, so it is never a place for terminals or logins. Android may later be a
-- real rootless host; that is not this change.
--
-- What changes:
-- - `remote_hosts.mode` also admits `device`;
-- - `remote_hosts.execution_uid` may be NULL, and is NULL exactly for a device:
--   the uid's own CHECK now says `(mode = 'device') = (execution_uid IS NULL)`.
--   The old `rootful = uid 0` and `rootless = uid != 0` rules stay as they were;
-- - `remote_join_tokens.mode` also admits `device`, and a P-256 invitation exists
--   only for a device and a device holds only a P-256 one (owner question Q4);
-- - a certificate's key algorithm must match its host's mode (a trigger, so every
--   writer of certificates is held to it: join, renewal, rotation, recovery);
-- - a device has no agent to uninstall or to confirm a login cleanup, so its
--   retirement obligation is born confirmed.
--
-- How, and why not a table rebuild. SQLite cannot change a CHECK or drop NOT NULL
-- in place, and the usual rebuild (create, copy, drop, rename) cannot run here:
-- `remote_hosts` is the parent of fourteen tables, several `ON DELETE CASCADE`
-- or `RESTRICT`, the runner applies a migration inside one transaction, and
-- `PRAGMA foreign_keys = OFF` does nothing inside a transaction. Dropping the
-- parent would cascade-delete its children's rows or refuse. SQLite documents the
-- way to loosen constraints without touching rows: rewrite the table's stored
-- `CREATE TABLE` text through `writable_schema` (https://sqlite.org/lang_altertable.html,
-- "Making Other Kinds Of Table Schema Changes"). Every stored row already
-- satisfies the looser rules, so nothing is revalidated or moved, no index or
-- foreign key is touched, and the edit commits or rolls back with the rest.
--
-- The new text is written out in full, not patched with `replace`: the stored text
-- of an existing database depends on how it was created (older databases keep the
-- migration's own spacing, newer ones the build's compacted form), so no pattern
-- would match both. The column list is the table's own, in its own order (the rows
-- keep their layout); the guard below compares it. `PRAGMA writable_schema = RESET`
-- reloads the connection's schema in the same transaction (a malformed text fails
-- there and the migration rolls back), and the trigger changes below bump the
-- schema cookie so the pool's other connections reload too.
PRAGMA writable_schema = ON;

UPDATE sqlite_schema
SET sql = 'CREATE TABLE remote_hosts (
    id BLOB PRIMARY KEY NOT NULL CHECK (length(id) = 16),
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    mode TEXT NOT NULL CHECK (mode IN (''rootless'', ''rootful'', ''device'')),
    execution_uid BIGINT CHECK ((mode = ''device'') = (execution_uid IS NULL) AND (execution_uid IS NULL OR execution_uid BETWEEN 0 AND 4294967295)),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    revoked_at BIGINT CHECK (revoked_at >= created_at),
    hostname TEXT CHECK(hostname IS NULL OR length(hostname) BETWEEN 1 AND 63),
    reported_os TEXT,
    device_approved INTEGER NOT NULL DEFAULT 0 CHECK (device_approved IN (0, 1)),
    device_os TEXT CHECK (device_os IS NULL OR length(device_os) BETWEEN 1 AND 256),
    CHECK (mode != ''rootful'' OR execution_uid = 0),
    CHECK (mode != ''rootless'' OR execution_uid != 0)
)'
WHERE type = 'table' AND name = 'remote_hosts';

UPDATE sqlite_schema
SET sql = 'CREATE TABLE remote_join_tokens (
    host_id BLOB PRIMARY KEY NOT NULL REFERENCES remote_hosts(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN (''rootless'', ''rootful'', ''device'')),
    digest BLOB NOT NULL UNIQUE CHECK (length(digest) = 32),
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0),
    expires_at BIGINT NOT NULL CHECK (
        expires_at > issued_at AND expires_at - issued_at IN (600, 900)
    ),
    consumed_at BIGINT CHECK (consumed_at >= issued_at AND consumed_at < expires_at),
    expected_key_digest BLOB CHECK (
        expected_key_digest IS NULL OR length(expected_key_digest) = 32
    ),
    key_algorithm TEXT NOT NULL DEFAULT ''ed25519''
        CHECK (key_algorithm IN (''ed25519'', ''p256'') AND (key_algorithm = ''p256'') = (mode = ''device''))
)'
WHERE type = 'table' AND name = 'remote_join_tokens';

PRAGMA writable_schema = RESET;

-- The reload parsed both texts; they must describe the very columns the rows have.
CREATE TEMP TABLE device_host_mode_guard (matched INTEGER NOT NULL CHECK (matched = 1));
INSERT INTO device_host_mode_guard VALUES ((
    SELECT group_concat(name || ':' || "notnull", ',') = 'id:1,owner_id:1,mode:1,execution_uid:0,created_at:1,revoked_at:0,hostname:0,reported_os:0,device_approved:1,device_os:0'
    FROM pragma_table_info('remote_hosts')));
INSERT INTO device_host_mode_guard VALUES ((
    SELECT group_concat(name || ':' || "notnull", ',') = 'host_id:1,mode:1,digest:1,issued_at:1,expires_at:1,consumed_at:0,expected_key_digest:0,key_algorithm:1'
    FROM pragma_table_info('remote_join_tokens')));
DROP TABLE device_host_mode_guard;

-- Changed from 20261105040921 in one place: a device's retirement obligation is
-- born confirmed. Every other mode inserts it unconfirmed exactly as before.
DROP TRIGGER remote_login_cleanup_on_retirement;
CREATE TRIGGER remote_login_cleanup_on_retirement
AFTER UPDATE OF revoked_at ON remote_hosts
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
    INSERT INTO remote_login_cleanup(host_id, person_id, confirmed)
    VALUES (NEW.id, NEW.owner_id, NEW.mode = 'device')
    ON CONFLICT(host_id) DO UPDATE SET person_id=excluded.person_id, confirmed=excluded.confirmed;
END;

-- A P-256 certificate belongs to a device and a device holds only P-256
-- certificates, whichever code path writes them (join, renewal, rotation or
-- recovery). The server's checks refuse the same shapes earlier; this is the
-- last line.
CREATE TRIGGER remote_certificates_key_matches_host_mode
BEFORE INSERT ON remote_certificates
WHEN (NEW.key_algorithm = 'p256') IS NOT
    COALESCE((SELECT h.mode = 'device' FROM remote_hosts h WHERE h.id = NEW.host_id), 0)
BEGIN
    SELECT RAISE(ABORT, 'a device holds a P-256 key and no other host does');
END;
