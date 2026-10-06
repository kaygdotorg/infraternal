-- Persist input acknowledgement by durable browser writer, not shared terminal output session [50].
CREATE TABLE terminal_writers (
    writer_id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (writer_id <= 2147483647),
    connection_id BLOB NOT NULL REFERENCES websocket_connections(connection_id) ON DELETE CASCADE,
    client_stream INTEGER NOT NULL CHECK (client_stream > 0 AND client_stream % 2 = 1),
    session_id BLOB NOT NULL REFERENCES terminal_sessions(id) ON DELETE CASCADE,
    input_acked BLOB NOT NULL DEFAULT X'0000000000000000' CHECK (length(input_acked) = 8),
    UNIQUE (connection_id, client_stream)
);
