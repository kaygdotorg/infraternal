-- Binds terminal ownership to its enrolled host without changing embedded sessions [9][64], #78.
-- NULL preserves the embedded route. Host tombstones remain referenced so a
-- removed host's sessions cannot silently move to a different machine.
ALTER TABLE terminal_sessions
    ADD COLUMN remote_host_id BLOB REFERENCES remote_hosts(id) ON DELETE RESTRICT
    CHECK (remote_host_id IS NULL OR length(remote_host_id) = 16);
