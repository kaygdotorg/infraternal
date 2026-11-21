-- Retire Mesh membership when a host's removal is committed, not when the host confirms it [166], #515.
--
-- A person's host (UUID owner) is removed in two steps: the removal intent
-- inserts an unconfirmed remote_login_cleanup row, and remote_hosts.revoked_at
-- is set only when the host later sends its cleanup receipt. Until now the
-- mesh node was retired only by 0024's trigger on revoked_at, so an offline,
-- stolen or blocked host kept its key on every peer with no time limit. D166
-- says removal cuts the node off even while it is offline.
--
-- Invariant: a host with an unconfirmed login cleanup has no Mesh membership.
-- Ordinary admission already refuses such a host (enrollment.rs), and its
-- cleanup-only reconnect is never published to plugins, so retiring the node
-- here cannot break the receipt: the host reaches the server on its enrolled
-- address, not through the mesh.
--
-- The body is 0024's retirement keyed by the cleanup row's host. When the
-- receipt later sets revoked_at, 0024's trigger finds no node: the tombstone
-- insert is ignored and the revision is not bumped a second time. A trigger,
-- rather than a second copy in Rust, keeps every writer of a pending removal
-- covered: Remove host, session revocation and startup bootstrap retirement.
CREATE TRIGGER remote_login_cleanup_retire_mesh AFTER INSERT ON remote_login_cleanup
WHEN NEW.confirmed = 0
BEGIN
    SELECT RAISE(ABORT, 'Mesh revision exhausted') WHERE
        (SELECT revision FROM mesh_state WHERE singleton=1)=9223372036854775807 AND EXISTS
        (SELECT 1 FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.host_id)));
    INSERT OR IGNORE INTO mesh_dataplane_removed(host)
        VALUES(lower(substr(hex(NEW.host_id),1,8)||'-'||substr(hex(NEW.host_id),9,4)||'-'||
                     substr(hex(NEW.host_id),13,4)||'-'||substr(hex(NEW.host_id),17,4)||'-'||
                     substr(hex(NEW.host_id),21,12)));
    DELETE FROM mesh_grants WHERE
        (from_kind='node' AND from_value IN
            (SELECT CAST(id AS TEXT) FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.host_id)))) OR
        (to_kind='node' AND to_value IN
            (SELECT CAST(id AS TEXT) FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.host_id))));
    UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND EXISTS
        (SELECT 1 FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.host_id)));
    DELETE FROM mesh_nodes WHERE replace(dataplane_host,'-','')=lower(hex(NEW.host_id));
END;

-- Removals already pending when this server upgrades lose their membership now,
-- with one revision bump for the whole set, as 0024 did for revoked hosts.
INSERT OR IGNORE INTO mesh_dataplane_removed(host)
    SELECT lower(substr(hex(host_id),1,8)||'-'||substr(hex(host_id),9,4)||'-'||
                 substr(hex(host_id),13,4)||'-'||substr(hex(host_id),17,4)||'-'||substr(hex(host_id),21,12))
    FROM remote_login_cleanup WHERE confirmed=0;
DELETE FROM mesh_grants WHERE
    (from_kind='node' AND from_value IN
        (SELECT CAST(n.id AS TEXT) FROM mesh_nodes n JOIN remote_login_cleanup q
         ON replace(n.dataplane_host,'-','')=lower(hex(q.host_id)) WHERE q.confirmed=0)) OR
    (to_kind='node' AND to_value IN
        (SELECT CAST(n.id AS TEXT) FROM mesh_nodes n JOIN remote_login_cleanup q
         ON replace(n.dataplane_host,'-','')=lower(hex(q.host_id)) WHERE q.confirmed=0));
UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND EXISTS
    (SELECT 1 FROM mesh_nodes n JOIN remote_login_cleanup q
     ON replace(n.dataplane_host,'-','')=lower(hex(q.host_id)) WHERE q.confirmed=0);
DELETE FROM mesh_nodes WHERE id IN
    (SELECT n.id FROM mesh_nodes n JOIN remote_login_cleanup q
     ON replace(n.dataplane_host,'-','')=lower(hex(q.host_id)) WHERE q.confirmed=0);
