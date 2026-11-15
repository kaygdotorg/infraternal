-- remote certificate role.
--
-- A certificate now says what it may be used for and which uid it was issued
-- for (D376, #399, J415 R1). Until now admission took the mode and uid from the
-- host row only, so a certificate issued for a host's root successor would have
-- been admitted as the rootless infraternal agent (and the reverse after the
-- upgrade).
--
-- - `role='active'`: the host's ordinary identity. Only these are admitted by
--   ordinary admission, and only while `execution_uid` equals the host's.
-- - `role='successor'`: the root infraternal agent installed by an upgrade that
--   hasn't handed over yet. Only the separate successor check admits it, and
--   only while its promotion row names it.
--
-- `execution_uid` stays NULL-able so the column can be added in place, but
-- admission compares it with `=`, so a row written without it is never
-- admitted: forgetting it fails closed. Every existing row is backfilled with
-- its host's uid.
ALTER TABLE remote_certificates
    ADD COLUMN role TEXT NOT NULL DEFAULT 'active' CHECK (role IN ('active', 'successor'));
ALTER TABLE remote_certificates
    ADD COLUMN execution_uid BIGINT CHECK (execution_uid IS NULL OR execution_uid BETWEEN 0 AND 4294967295);

UPDATE remote_certificates
SET execution_uid = (SELECT h.execution_uid FROM remote_hosts h WHERE h.id = remote_certificates.host_id);

-- A successor is always root: the upgrade only goes rootless to root (D376).
CREATE TRIGGER remote_certificates_successor_is_root_insert
BEFORE INSERT ON remote_certificates
WHEN NEW.role = 'successor' AND NEW.execution_uid IS NOT 0
BEGIN
    SELECT RAISE(ABORT, 'a successor certificate is for uid 0');
END;

-- A certificate's uid never changes, and a role changes only successor→active,
-- at the upgrade's handover (see the promotions migration). Nothing turns an
-- active certificate into a successor.
CREATE TRIGGER remote_certificates_role_write_once
BEFORE UPDATE OF role, execution_uid ON remote_certificates
WHEN NEW.execution_uid IS NOT OLD.execution_uid
    OR (NEW.role IS NOT OLD.role AND NOT (OLD.role = 'successor' AND NEW.role = 'active'))
BEGIN
    SELECT RAISE(ABORT, 'certificate role and uid are write-once');
END;
