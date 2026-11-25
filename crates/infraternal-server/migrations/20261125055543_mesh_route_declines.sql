-- Declined subnet routes (D197 M3, #580; owner 2026-11-25: "Decline is remembered").
--
-- The owner may turn down a network a machine advertises. The decline is kept on the row, so
-- the network stops waiting for approval and does not ask again when the machine re-advertises
-- it. A declined row also survives the machine withdrawing the network (`record_routes` forgets
-- only rows that are neither approved nor declined). Approving it later clears the decline.
-- A row is never both approved and declined.
ALTER TABLE mesh_routes ADD COLUMN declined_at INTEGER;
ALTER TABLE mesh_routes ADD COLUMN declined_by TEXT
    CHECK ((declined_at IS NULL) = (declined_by IS NULL));
