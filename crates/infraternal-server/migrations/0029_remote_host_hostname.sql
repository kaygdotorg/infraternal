-- Retain reported hostnames and replace legacy UUID placeholders without changing existing names, #236.
ALTER TABLE remote_hosts ADD COLUMN hostname TEXT CHECK(hostname IS NULL OR length(hostname) BETWEEN 1 AND 63);

-- Share one allocation with the audit. The existing name index reserves candidates with its own collation.
CREATE TEMP TABLE _hostname_labels(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE);
WITH RECURSIVE labels(id,suffix,name) AS (
    SELECT id,0,'unnamed-'||id FROM mesh_nodes
    WHERE name_source='placeholder' AND dataplane_host!='server' AND name='mesh-'||dataplane_host
    UNION ALL
    SELECT id,suffix+1,'unnamed-'||id||'-'||(suffix+1) FROM labels
    WHERE EXISTS(SELECT 1 FROM mesh_nodes WHERE mesh_nodes.name=labels.name)
)
INSERT INTO _hostname_labels SELECT id,name FROM labels
WHERE NOT EXISTS(SELECT 1 FROM mesh_nodes WHERE mesh_nodes.name=labels.name);

UPDATE mesh_state SET revision=revision+1
WHERE singleton=1 AND EXISTS(SELECT 1 FROM _hostname_labels);
INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json)
SELECT u.id,'mesh.node.name',CAST(n.id AS TEXT),s.revision,unixepoch(),
       json_object('node_id',n.id,'name',labels.name,'previous',n.name,
                   'source','placeholder','automatic',json('true'))
FROM mesh_nodes n JOIN _hostname_labels labels ON labels.id=n.id
JOIN (SELECT id FROM users WHERE owner=1 ORDER BY rowid LIMIT 1) u
JOIN mesh_state s ON s.singleton=1;
UPDATE mesh_nodes SET name=(SELECT name FROM _hostname_labels WHERE id=mesh_nodes.id)
WHERE id IN(SELECT id FROM _hostname_labels);
DROP TABLE _hostname_labels;
