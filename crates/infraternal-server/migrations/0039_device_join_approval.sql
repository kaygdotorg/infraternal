-- Additive D311 request kinds for fresh-passkey machine enrollment [#263].
ALTER TABLE approvals ADD COLUMN kind TEXT NOT NULL DEFAULT 'sign_in'
    CHECK (kind IN ('sign_in', 'join_machine'));
ALTER TABLE approvals ADD COLUMN request_json TEXT;
ALTER TABLE approvals ADD COLUMN approved_session_hash TEXT;
ALTER TABLE approvals ADD COLUMN inspect_attempts INTEGER NOT NULL DEFAULT 0
    CHECK (inspect_attempts BETWEEN 0 AND 5);
