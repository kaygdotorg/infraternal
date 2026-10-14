-- Shares durable even native writer IDs between terminals and plugin streams [D12,D198,D232].
-- Seed from AUTOINCREMENT, including identities whose rows were deleted.
CREATE TABLE wire_writer_clock (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    value INTEGER NOT NULL CHECK(value>=0 AND value<=2147483647)
) STRICT;
INSERT INTO wire_writer_clock(singleton,value)
VALUES(1,MIN(2147483647,MAX(0,COALESCE((SELECT seq FROM sqlite_sequence WHERE name='terminal_writers'),0))));
