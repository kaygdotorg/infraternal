-- Persistent terminal ownership belongs to users, so every device can attach to the same session [50].
CREATE TABLE terminal_sessions (
    id BLOB PRIMARY KEY NOT NULL CHECK (length(id) = 16),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    last_seen BIGINT NOT NULL,
    input_acked BIGINT NOT NULL DEFAULT 0 CHECK (input_acked >= 0),
    closed_at BIGINT,
    exit_status INTEGER
);

CREATE INDEX terminal_sessions_user ON terminal_sessions(user_id, last_seen);
