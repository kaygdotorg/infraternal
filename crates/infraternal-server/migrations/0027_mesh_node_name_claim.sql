-- The name a Mesh node's automatic source asked for, before any collision suffix (#236). A node moved aside
-- (`minipc01-2` taken by a stronger claim) is renamed after its own claim (`minipc01-3`), never after the
-- claimant's (`minipc01-2-2`), so its next attach finds it already where it belongs and renames nothing.
-- NULL means the claim is the name itself: placeholders, names a person chose, and rows written before this.
ALTER TABLE mesh_nodes ADD COLUMN name_claim TEXT;
