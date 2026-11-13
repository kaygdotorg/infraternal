-- mesh direct candidates.
-- Where a node can be reached besides the control-IP guess in `endpoint` (#515, D391, D316):
-- the public address and port the server's mesh device last saw its packets come from, and the
-- private default-route addresses it reported for peers behind the same public address (a JSON
-- array of at most two "ip:port" strings). Both are public coordinates, never credentials.
-- `candidates_supported` records that the node walks an ordered candidate list; older nodes keep
-- receiving one endpoint, because their snapshot decoder refuses unknown fields.
ALTER TABLE mesh_nodes ADD COLUMN reflexive_endpoint TEXT;
ALTER TABLE mesh_nodes ADD COLUMN lan_endpoints TEXT;
ALTER TABLE mesh_nodes ADD COLUMN candidates_supported INTEGER NOT NULL DEFAULT 0
    CHECK (candidates_supported IN (0, 1));
