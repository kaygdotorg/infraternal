-- mesh epoch capability.
-- Keep an unknown probe distinct from a proved old node; the public restore_safe view fails closed [166,352], #382.
ALTER TABLE mesh_nodes ADD COLUMN authority_epoch_supported INTEGER
    CHECK (authority_epoch_supported IS NULL OR authority_epoch_supported IN (0, 1));
