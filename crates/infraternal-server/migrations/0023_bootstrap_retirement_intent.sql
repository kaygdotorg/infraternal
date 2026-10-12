-- Retire unfinished host provisioning after cancellation or restart (#169).
-- Existing installations have no intent. New invitations insert one in their
-- own transaction; proven completion alone removes it without revocation.
CREATE TABLE remote_bootstrap_retirement_intents (
    host_id BLOB PRIMARY KEY NOT NULL REFERENCES remote_hosts(id) ON DELETE CASCADE
);
