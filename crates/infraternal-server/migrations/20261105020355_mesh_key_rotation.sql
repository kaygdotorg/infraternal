-- Persist the WireGuard rotation cadence and public overlap state [166], #285.
ALTER TABLE mesh_dataplane ADD COLUMN rotation_period_secs INTEGER NOT NULL DEFAULT 604800
    CHECK (rotation_period_secs > 0);
ALTER TABLE mesh_nodes ADD COLUMN key_rotation_supported INTEGER NOT NULL DEFAULT 0
    CHECK (key_rotation_supported IN (0, 1));

CREATE TABLE mesh_node_key_rotation (
    node_id INTEGER PRIMARY KEY REFERENCES mesh_nodes(id) ON DELETE CASCADE,
    last_rotation INTEGER NOT NULL DEFAULT (unixepoch()),
    schedule_boot_id TEXT NOT NULL DEFAULT 'unknown',
    schedule_monotonic INTEGER NOT NULL DEFAULT 0 CHECK (schedule_monotonic >= 0),
    schedule_period_secs INTEGER NOT NULL DEFAULT 604800 CHECK (schedule_period_secs > 0),
    candidate_public_key BLOB CHECK (candidate_public_key IS NULL OR length(candidate_public_key) = 32),
    previous_public_key BLOB CHECK (previous_public_key IS NULL OR length(previous_public_key) = 32),
    rotation_phase TEXT CHECK (rotation_phase IS NULL OR rotation_phase IN ('preparing', 'overlap', 'retiring', 'cleanup')),
    rotation_started_at INTEGER,
    rotation_boot_id TEXT,
    rotation_monotonic INTEGER CHECK (rotation_monotonic IS NULL OR rotation_monotonic >= 0),
    operation_id TEXT,
    sequence INTEGER NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    rotation_revision INTEGER CHECK (rotation_revision IS NULL OR rotation_revision >= 0),
    local_committed INTEGER NOT NULL DEFAULT 0 CHECK (local_committed IN (0, 1)),
    CHECK (
        (rotation_phase IS NULL AND candidate_public_key IS NULL AND previous_public_key IS NULL AND rotation_started_at IS NULL AND rotation_boot_id IS NULL
            AND rotation_monotonic IS NULL AND operation_id IS NULL AND rotation_revision IS NULL
            AND local_committed = 0)
        OR
        (rotation_phase = 'preparing' AND candidate_public_key IS NULL AND previous_public_key IS NULL AND rotation_started_at IS NULL
            AND rotation_boot_id IS NULL AND rotation_monotonic IS NULL
            AND operation_id IS NOT NULL AND rotation_revision IS NULL AND local_committed = 0)
        OR
        (rotation_phase = 'overlap' AND candidate_public_key IS NOT NULL AND previous_public_key IS NOT NULL AND rotation_started_at IS NOT NULL
            AND rotation_boot_id IS NOT NULL AND rotation_monotonic IS NOT NULL
            AND operation_id IS NOT NULL AND rotation_revision IS NOT NULL AND local_committed = 0)
        OR
        (rotation_phase = 'retiring' AND candidate_public_key IS NULL AND previous_public_key IS NOT NULL AND rotation_started_at IS NOT NULL
            AND rotation_boot_id IS NOT NULL AND rotation_monotonic IS NOT NULL
            AND operation_id IS NOT NULL AND rotation_revision IS NOT NULL AND local_committed = 1)
        OR
        (rotation_phase = 'cleanup' AND candidate_public_key IS NULL AND previous_public_key IS NULL AND rotation_started_at IS NOT NULL
            AND rotation_boot_id IS NOT NULL AND rotation_monotonic IS NOT NULL
            AND operation_id IS NOT NULL AND rotation_revision IS NOT NULL AND local_committed = 1)
    )
);

INSERT INTO mesh_node_key_rotation(node_id, last_rotation)
    SELECT id, unixepoch() FROM mesh_nodes;

CREATE TRIGGER mesh_node_rotation_seed AFTER INSERT ON mesh_nodes BEGIN
    INSERT INTO mesh_node_key_rotation(node_id) VALUES (NEW.id);
END;

-- An acknowledgement belongs to one server process; a restart uses a new id and must reapply views.
CREATE TABLE mesh_node_applied (
    node_id INTEGER PRIMARY KEY REFERENCES mesh_nodes(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    server_instance TEXT NOT NULL
);

CREATE INDEX mesh_node_applied_instance_revision
    ON mesh_node_applied(server_instance, revision, node_id);
