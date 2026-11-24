-- Subnet routes (D197 M3, #580): networks a node advertises, and the administrator's approval of each.
--
-- `mesh_routes` holds one row per (node, network) the node advertises or that is approved:
-- - `advertised` is the node's own, latest word (the `{"routes":true}` identity probe). A network
--   the node stops advertising keeps its approval but is not routed until the node advertises it
--   again: no route ever runs without the router's consent.
-- - `approved_at`/`approved_by` are NULL while the network waits for an administrator.
-- - `masquerade` (default on) rewrites forwarded sources to the router's own address; off keeps
--   the peer's real mesh address.
-- - `id` is AUTOINCREMENT so an identity is never reused: arrows name it, and a revoked approval
--   (row deleted) must never come back to life through an old arrow when the same network is
--   approved again later.
-- Rows go with their node (ON DELETE CASCADE; the pool enables foreign keys).
CREATE TABLE mesh_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL REFERENCES mesh_nodes(id) ON DELETE CASCADE,
    network TEXT NOT NULL,
    advertised INTEGER NOT NULL DEFAULT 1 CHECK (advertised IN (0, 1)),
    approved_at INTEGER,
    approved_by TEXT,
    masquerade INTEGER NOT NULL DEFAULT 1 CHECK (masquerade IN (0, 1)),
    CHECK ((approved_at IS NULL) = (approved_by IS NULL)),
    UNIQUE (node_id, network)
);

-- Whether the node understands subnet routes in its snapshots (`PeerPolicy::networks`) and
-- reports what it advertises. Older nodes refuse unknown fields, so they never get the field.
ALTER TABLE mesh_nodes ADD COLUMN routes_supported INTEGER NOT NULL DEFAULT 0
    CHECK (routes_supported IN (0, 1));

-- An approved network is the target of access arrows: `to_kind = 'network'`, `to_value` = the
-- `mesh_routes.id`. A network is never a source (the mesh model refuses it as well), so only
-- `to_kind` widens. SQLite cannot change a CHECK in place, so the table is rebuilt.
-- `legacy_alter_table` keeps the rename from rewriting or re-parsing the triggers on other
-- tables that delete from `mesh_grants` by name (0024 and the removal-intent trigger); they
-- resolve the name at run time and find the rebuilt table.
PRAGMA legacy_alter_table = ON;
CREATE TABLE mesh_grants_v2 (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE BINARY,
    from_kind TEXT NOT NULL CHECK (from_kind IN ('node', 'tag')),
    from_value TEXT NOT NULL,
    to_kind TEXT NOT NULL CHECK (to_kind IN ('node', 'tag', 'network')),
    to_value TEXT NOT NULL,
    both_ways INTEGER NOT NULL CHECK (both_ways IN (0, 1)),
    ports_json TEXT NOT NULL,
    CHECK (to_kind != 'network' OR both_ways = 0)
);
INSERT INTO mesh_grants_v2 (id, name, from_kind, from_value, to_kind, to_value, both_ways, ports_json)
    SELECT id, name, from_kind, from_value, to_kind, to_value, both_ways, ports_json FROM mesh_grants;
DROP TABLE mesh_grants;
ALTER TABLE mesh_grants_v2 RENAME TO mesh_grants;
PRAGMA legacy_alter_table = OFF;
CREATE INDEX mesh_grants_from ON mesh_grants(from_kind, from_value);
CREATE INDEX mesh_grants_to ON mesh_grants(to_kind, to_value);
