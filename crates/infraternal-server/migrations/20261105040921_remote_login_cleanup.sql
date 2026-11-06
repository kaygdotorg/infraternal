-- Retain authorized host-login cleanup until the daemon confirms durability.
-- The host tombstone and this outbox row commit in the same transaction.
CREATE TABLE remote_login_cleanup (
    host_id BLOB PRIMARY KEY REFERENCES remote_hosts(id) ON DELETE CASCADE,
    person_id TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0 CHECK (confirmed IN (0, 1))
) STRICT;

-- Older unconfirmed retirements must also remain eligible for cleanup replay.
INSERT INTO remote_login_cleanup(host_id, person_id)
SELECT id, owner_id FROM remote_hosts WHERE revoked_at IS NOT NULL;

-- Every host retirement path, including startup bootstrap recovery, owns an
-- outbox obligation in its existing writer transaction.
CREATE TRIGGER remote_login_cleanup_on_retirement
AFTER UPDATE OF revoked_at ON remote_hosts
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
    INSERT INTO remote_login_cleanup(host_id, person_id)
    VALUES (NEW.id, NEW.owner_id)
    ON CONFLICT(host_id) DO UPDATE SET person_id=excluded.person_id, confirmed=0;
END;
