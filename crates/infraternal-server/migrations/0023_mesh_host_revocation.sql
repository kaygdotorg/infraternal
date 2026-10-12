-- Retire Mesh membership and node grants in the host revocation transaction [134,166,235], #173.
-- Host UUIDs are stored as bytes in the authority ledger and canonical text in Mesh.
-- This invariant covers every authority writer, including restoration of older databases.
CREATE TRIGGER remote_hosts_retire_mesh AFTER UPDATE OF revoked_at ON remote_hosts
WHEN NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'Mesh revision exhausted') WHERE
        (SELECT revision FROM mesh_state WHERE singleton=1)=9223372036854775807 AND EXISTS
        (SELECT 1 FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.id)));
    INSERT OR IGNORE INTO mesh_dataplane_removed(host)
        VALUES(lower(substr(hex(NEW.id),1,8)||'-'||substr(hex(NEW.id),9,4)||'-'||
                     substr(hex(NEW.id),13,4)||'-'||substr(hex(NEW.id),17,4)||'-'||substr(hex(NEW.id),21,12)));
    DELETE FROM mesh_grants WHERE
        (from_kind='node' AND from_value IN
            (SELECT CAST(id AS TEXT) FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.id)))) OR
        (to_kind='node' AND to_value IN
            (SELECT CAST(id AS TEXT) FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.id))));
    UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND EXISTS
        (SELECT 1 FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.id)));
    DELETE FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.id));
END;

-- Historical tombstones must not regain packet authority after a server upgrade.
INSERT OR IGNORE INTO mesh_dataplane_removed(host)
    SELECT lower(substr(hex(id),1,8)||'-'||substr(hex(id),9,4)||'-'||
                 substr(hex(id),13,4)||'-'||substr(hex(id),17,4)||'-'||substr(hex(id),21,12))
    FROM remote_hosts WHERE revoked_at IS NOT NULL;
DELETE FROM mesh_grants WHERE
    (from_kind='node' AND from_value IN
        (SELECT CAST(n.id AS TEXT) FROM mesh_nodes n JOIN remote_hosts h
         ON replace(n.dataplane_host,'-','')=lower(hex(h.id)) WHERE h.revoked_at IS NOT NULL)) OR
    (to_kind='node' AND to_value IN
        (SELECT CAST(n.id AS TEXT) FROM mesh_nodes n JOIN remote_hosts h
         ON replace(n.dataplane_host,'-','')=lower(hex(h.id)) WHERE h.revoked_at IS NOT NULL));
UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND EXISTS
    (SELECT 1 FROM mesh_nodes n JOIN remote_hosts h
     ON replace(n.dataplane_host,'-','')=lower(hex(h.id)) WHERE h.revoked_at IS NOT NULL);
DELETE FROM mesh_nodes WHERE id IN
    (SELECT n.id FROM mesh_nodes n JOIN remote_hosts h
     ON replace(n.dataplane_host,'-','')=lower(hex(h.id)) WHERE h.revoked_at IS NOT NULL);
