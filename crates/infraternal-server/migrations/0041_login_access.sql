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

-- Mesh SSH (#221). Off for every machine until the owner turns it on (Q4).
-- host is the node identity: 'server' or the remote host ID.
CREATE TABLE mesh_ssh_hosts (
    host TEXT PRIMARY KEY NOT NULL CHECK (length(host) BETWEEN 1 AND 64),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
);
-- Issued person certificates by full digest; a target accepts only these.
CREATE TABLE mesh_ssh_certificates (
    digest BLOB PRIMARY KEY NOT NULL CHECK (length(digest) = 32),
    person TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    source_node INTEGER NOT NULL CHECK (source_node >= 0),
    source_address TEXT NOT NULL,
    valid_before BIGINT NOT NULL CHECK (valid_before >= 0)
);
CREATE INDEX mesh_ssh_certificates_person ON mesh_ssh_certificates (person, host);
-- Snapshot sequence; strictly increasing and never below the clock.
CREATE TABLE mesh_ssh_sequence (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    value INTEGER NOT NULL CHECK (value >= 0)
);
INSERT INTO mesh_ssh_sequence (singleton, value) VALUES (1, 0);
-- Every certificate the CA issued for mesh SSH, person and host, for audit (J181 M6).
CREATE TABLE mesh_ssh_issued (
    digest BLOB PRIMARY KEY NOT NULL CHECK (length(digest) = 32),
    kind TEXT NOT NULL CHECK (kind IN ('person', 'host')),
    principals TEXT NOT NULL CHECK (json_valid(principals)),
    valid_before BIGINT NOT NULL CHECK (valid_before >= 0),
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0)
);
