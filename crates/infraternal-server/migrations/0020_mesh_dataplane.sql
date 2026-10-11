-- Bind authenticated hosts to public Mesh inventory and retain stable allocations/default policy [165,166,216].
-- Membership has no expiry. Null policy selects the edition default without changing historical rows.
ALTER TABLE mesh_nodes ADD COLUMN dataplane_host TEXT;
ALTER TABLE mesh_nodes ADD COLUMN endpoint TEXT;
CREATE UNIQUE INDEX mesh_nodes_dataplane_host ON mesh_nodes(dataplane_host) WHERE dataplane_host IS NOT NULL;
CREATE TABLE mesh_dataplane (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    allocation_json TEXT CHECK (allocation_json IS NULL OR json_valid(allocation_json)),
    default_policy TEXT CHECK (default_policy IS NULL OR default_policy IN ('allow','deny'))
);
INSERT INTO mesh_dataplane(singleton) VALUES(1);

-- An authenticated reconnect is not permission to restore removed membership.
CREATE TABLE mesh_dataplane_removed (
    host TEXT PRIMARY KEY
) WITHOUT ROWID;
