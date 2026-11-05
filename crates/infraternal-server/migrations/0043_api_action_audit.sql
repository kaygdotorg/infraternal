-- Retain action attribution without storing API-key or action payload plaintext.
CREATE TABLE api_action_audit (
    id INTEGER PRIMARY KEY,
    key_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    target_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'denied', 'failed')),
    occurred_at INTEGER NOT NULL,
    completed_at INTEGER,
    result TEXT
);

CREATE INDEX api_action_audit_person_time
    ON api_action_audit(person_id, occurred_at DESC, id DESC);
