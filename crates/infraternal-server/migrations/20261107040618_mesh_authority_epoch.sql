-- Persist the deployment authority separately from process-lifetime rotation receipts [166,285,352], #382.
-- NULL is an explicit restore reset; the coordinator replaces it durably before publishing a snapshot.
ALTER TABLE mesh_state ADD COLUMN authority_epoch TEXT;
