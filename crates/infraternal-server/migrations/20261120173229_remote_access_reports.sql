-- D356: access files of a host account that changed since a person's login
-- was granted, as returned by the host when it revoked that login. File paths
-- and line text only, bounded by the server before it is written here. Kept
-- per host and person for the owner to read; written in the transaction that
-- confirms the revocation.
CREATE TABLE remote_access_reports (
    host_id BLOB NOT NULL REFERENCES remote_hosts(id) ON DELETE CASCADE,
    person_id TEXT NOT NULL,
    report TEXT NOT NULL CHECK (length(CAST(report AS BLOB)) <= 32768),
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (host_id, person_id)
) STRICT;
