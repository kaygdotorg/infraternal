-- Recovery authority measures recorded monotonic process uptime, never wall time [D25], #309.
-- Clock ticks and recovery ready/expires are elapsed nanoseconds.
CREATE TABLE recovery_clock (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    elapsed BIGINT NOT NULL CHECK(elapsed>=0)
);
INSERT INTO recovery_clock(singleton,elapsed) VALUES(1,0);
-- Old wall deadlines cannot prove elapsed time or continued validity. End these
-- requests rather than revive an expired bearer. Words can start a fresh wait.
DELETE FROM recovery;
