-- Retain the last valid hostname reported by an admitted host, including hosts added by IP, #236.
ALTER TABLE remote_hosts ADD COLUMN hostname TEXT CHECK(hostname IS NULL OR length(hostname) BETWEEN 1 AND 63);

-- Replace persisted pre-fix UUID labels immediately, even before an old host reconnects or reports a hostname.
UPDATE mesh_state SET revision=revision+1
WHERE singleton=1 AND EXISTS(
    SELECT 1 FROM mesh_nodes
    WHERE name_source='placeholder' AND dataplane_host!='server'
      AND name='mesh-'||dataplane_host
);
INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json)
SELECT u.id,'mesh.node.name',CAST(n.id AS TEXT),s.revision,unixepoch(),
       json_object('node_id',n.id,'name','unnamed-'||n.id,'previous',n.name,
                   'source','placeholder','automatic',json('true'))
FROM mesh_nodes n
JOIN (SELECT id FROM users WHERE owner=1 ORDER BY rowid LIMIT 1) u
JOIN mesh_state s ON s.singleton=1
WHERE n.name_source='placeholder' AND n.dataplane_host!='server'
  AND n.name='mesh-'||n.dataplane_host;
UPDATE mesh_nodes SET name='unnamed-'||id
WHERE name_source='placeholder' AND dataplane_host!='server'
  AND name='mesh-'||dataplane_host;
