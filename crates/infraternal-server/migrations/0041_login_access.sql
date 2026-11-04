-- Login access rules: which person may become which account on which host [D235, D252, D319], #186, #221.
-- subject NULL means everyone. host_id NULL means all hosts; an empty blob is the server's own host.
-- There are no negative rules: rows only ever allow.
CREATE TABLE login_rules (
    id INTEGER PRIMARY KEY,
    subject TEXT REFERENCES users(id) ON DELETE CASCADE,
    account_kind TEXT NOT NULL CHECK (account_kind IN ('own', 'any', 'named')),
    account TEXT CHECK (
        (account_kind = 'named') = (account IS NOT NULL)
        AND (account IS NULL OR length(account) BETWEEN 1 AND 32)
    ),
    host_id BLOB CHECK (host_id IS NULL OR length(host_id) IN (0, 16)),
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);
CREATE UNIQUE INDEX login_rules_unique ON login_rules (
    COALESCE(subject, ''), account_kind, COALESCE(account, ''), COALESCE(host_id, X'FF')
);
CREATE INDEX login_rules_subject ON login_rules (subject);

-- Machines an administrator marked "Names match people here" (D319).
CREATE TABLE login_names_match (
    host_id BLOB PRIMARY KEY NOT NULL CHECK (length(host_id) IN (0, 16))
);

-- The setup defaults are ordinary rows (D235 Q4): deleting one persists.
-- A server set up before this migration gets them once, here; a new server
-- gets the owner row when the owner is created.
INSERT INTO login_rules (subject, account_kind, account, host_id, created_at)
VALUES (NULL, 'own', NULL, NULL, unixepoch());
INSERT INTO login_rules (subject, account_kind, account, host_id, created_at)
SELECT id, 'any', NULL, NULL, unixepoch() FROM users WHERE owner = 1;
