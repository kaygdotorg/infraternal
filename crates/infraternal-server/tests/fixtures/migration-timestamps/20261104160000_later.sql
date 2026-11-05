-- Deliberately non-idempotent so an accidental second apply is observable.
CREATE TABLE IF NOT EXISTS timestamp_events (name TEXT NOT NULL);
INSERT INTO timestamp_events (name) VALUES ('later');
