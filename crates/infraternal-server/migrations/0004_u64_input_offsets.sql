-- SQLite INTEGER is signed; big-endian bytes preserve the full wire u64 range and order lexicographically [41].
ALTER TABLE terminal_sessions
    ADD COLUMN input_acked_u64 BLOB NOT NULL DEFAULT X'0000000000000000'
    CHECK (length(input_acked_u64) = 8);
