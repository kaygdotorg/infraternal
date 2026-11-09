-- host activity.
--
-- The host's activity log (D274, D376, #399): every privileged action on a host
-- (upgrade tries, wrong passwords, waits, upgrades, rollbacks) with who asked,
-- when, how and what came of it. It feeds the host's activity view and the
-- Inbox. It never holds a secret: every column is a fixed word, an id or a
-- time, and there is no free text from the host or the browser.
--
-- The upgrade's "2 tries, then wait" rule (D376) is computed from these rows,
-- so a server restart doesn't reset it.
CREATE TABLE host_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id BLOB NOT NULL CHECK (length(host_id) = 16),
    at BIGINT NOT NULL CHECK (at >= 0),
    -- The person who asked; kept as text so the log outlives the account.
    person TEXT NOT NULL CHECK (length(person) BETWEEN 1 AND 64),
    kind TEXT NOT NULL CHECK (kind IN (
        'privilege.attempt',
        'privilege.wrong',
        'privilege.locked',
        'privilege.denied',
        'privilege.upgraded',
        'privilege.rolled_back',
        'privilege.failed'
    )),
    -- The way in, for privilege rows.
    method TEXT CHECK (method IS NULL OR method IN ('sudo', 'doas', 'su')),
    -- The upgrade attempt this row belongs to, when there is one.
    attempt BLOB CHECK (attempt IS NULL OR length(attempt) = 16),
    -- A fixed reason word for failures and rollbacks (for example 'mismatch',
    -- 'timeout', 'join', 'start', 'handover'); never host output.
    reason TEXT CHECK (reason IS NULL OR (length(reason) BETWEEN 1 AND 32 AND reason NOT GLOB '*[^a-z_]*'))
);

CREATE INDEX host_activity_host_at ON host_activity(host_id, at);
