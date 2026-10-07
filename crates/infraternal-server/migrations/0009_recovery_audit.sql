-- Recovery lifecycle evidence contains account IDs and times, never words or capabilities [25,#45].
CREATE TABLE recovery_audit (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    event TEXT NOT NULL CHECK(event IN ('start','cancel','complete')),
    occurred_at BIGINT NOT NULL
);
CREATE INDEX recovery_audit_user ON recovery_audit(user_id,id);
