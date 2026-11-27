-- add mesh dataplane removal time.
-- Keep the most recent host-removal tombstones in relay lists, while dropping entries whose
-- host leaves have expired. This prevents permanent historical rows starving new revocations [D402].
ALTER TABLE mesh_dataplane_removed
    ADD COLUMN removed_at INTEGER NOT NULL DEFAULT 0 CHECK (removed_at >= 0);

-- Recover known removal times for existing rows. When a pending removal has no timestamp,
-- the newest issued leaf's start time keeps the tombstone until that leaf's seven-day life ends.
UPDATE mesh_dataplane_removed
SET removed_at = 1000 * MAX(
    COALESCE((SELECT requested_at FROM remote_host_removals
              WHERE lower(hex(host_id)) = replace(mesh_dataplane_removed.host, '-', '')), 0),
    COALESCE((SELECT revoked_at FROM remote_hosts
              WHERE lower(hex(id)) = replace(mesh_dataplane_removed.host, '-', '')), 0),
    COALESCE((SELECT MAX(not_before) FROM remote_certificates
              WHERE lower(hex(host_id)) = replace(mesh_dataplane_removed.host, '-', '')), 0)
);

CREATE INDEX mesh_dataplane_removed_recency
    ON mesh_dataplane_removed(removed_at DESC, host);

-- Milliseconds give the ordered list a monotonic tie-breaker even for removals in one second.
CREATE TRIGGER mesh_dataplane_removed_timestamp AFTER INSERT ON mesh_dataplane_removed
WHEN NEW.removed_at = 0
BEGIN
    UPDATE mesh_dataplane_removed
    SET removed_at = MAX(
        CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER),
        COALESCE((SELECT MAX(removed_at) + 1 FROM mesh_dataplane_removed
                  WHERE host != NEW.host), 1)
    )
    WHERE host = NEW.host;
END;
