-- Independent branch change: both fixture timestamps can arrive first.
CREATE TABLE IF NOT EXISTS timestamp_events (name TEXT NOT NULL);
INSERT INTO timestamp_events (name) VALUES ('earlier');
