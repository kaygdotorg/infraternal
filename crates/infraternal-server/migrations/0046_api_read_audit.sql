-- J154 P2-1 (#303): reads by API key are counted per key, action and minute instead of one
-- row per call, so a key cannot flood the audit and push out the record of its changes. The
-- row cap applies to this table only; `api_action_audit` keeps changes and denials for 90 days.
CREATE TABLE api_read_audit (
    key_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    minute INTEGER NOT NULL,
    calls INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    PRIMARY KEY (key_id, action_id, minute)
) WITHOUT ROWID;

CREATE INDEX api_read_audit_minute ON api_read_audit(minute);
