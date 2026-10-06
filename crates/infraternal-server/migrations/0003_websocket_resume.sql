-- Resume tokens are single-use while a connection is active and expire 120 seconds after disconnect [41].
CREATE TABLE websocket_connections (
    connection_id BLOB PRIMARY KEY NOT NULL CHECK (length(connection_id) = 16),
    token_hash BLOB NOT NULL CHECK (length(token_hash) = 32),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT,
    active INTEGER NOT NULL CHECK (active IN (0, 1))
);

CREATE INDEX websocket_connections_user ON websocket_connections(user_id, active, expires_at);
