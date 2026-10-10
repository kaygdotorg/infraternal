-- Preserve issued Mesh node references across deletion and restart [180].
ALTER TABLE mesh_state ADD COLUMN node_id_high_water INTEGER NOT NULL DEFAULT 0
    CHECK (node_id_high_water >= 0);

-- Enrollment audit rows retain identities of hosts already absent from inventory.
UPDATE mesh_state SET node_id_high_water = MAX(
    COALESCE((SELECT MAX(id) FROM mesh_nodes), 0),
    COALESCE((SELECT MAX(CAST(json_extract(detail_json, '$.node_id') AS INTEGER))
        FROM mesh_audit WHERE action = 'mesh.node.enroll'), 0)
);
