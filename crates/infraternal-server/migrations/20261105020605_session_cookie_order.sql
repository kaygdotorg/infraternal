-- Persistent browser cookies use one server-monotonic sequence per login [28, #285].
ALTER TABLE sessions ADD COLUMN login_sequence BIGINT NOT NULL DEFAULT 0 CHECK (login_sequence >= 0);
CREATE INDEX sessions_login_sequence ON sessions(login_sequence, expires);

CREATE TABLE session_login_sequence (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    value BIGINT NOT NULL CHECK (value >= 0)
);
INSERT INTO session_login_sequence(singleton, value) VALUES (1, 0);
