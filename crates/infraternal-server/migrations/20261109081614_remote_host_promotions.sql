-- remote host promotions.
--
-- One row per try at upgrading a host from the rootless infraternal agent to
-- the root one (D274, D376, #399; J415's R1, R3, R5 and R7). The row is the
-- only thing that may change a host's mode, and only one way: rootless to
-- root, in the handover transaction, while the row is `enrolled`.
--
-- Life of a row:
--   open        begun by a host admin's unlocked session inside its admin
--               window; a one-use seal key was asked for. Bound to the exact
--               rootless certificate and link generation seen then (R7).
--   elevating   the try was reserved (the 2-try check and this reservation are
--               one UPDATE, B2); the password, if any, is on its way to PAM.
--   installing  root was reached; the relay runs the root install steps. A
--               one-use successor join token is bound to the staged key.
--   enrolled    the successor redeemed that token; its certificate has
--               role 'successor' and is admitted only for proof calls.
--   handed_over the handover transaction committed: the host is rootful.
--   wrong       the password was refused (counts as a try).
--   failed      the try ended before root, for another reason; `tried` says
--               whether a password had already been typed (then it counts).
--   rolled_back the install failed before redemption and the host was put back.
--   abandoned   given up after redemption (or by the sweeper); handover can
--               never commit afterwards, because it requires `enrolled`.
--
-- `cleanup` is the durable outbox for the two endings that need the host's
-- own action (R5): 'uninstall' asks an abandoned successor to roll itself back
-- and remove itself; 'retire' asks the new root infraternal agent to retire
-- the rootless install. Each becomes 'done' on the host's receipt.
CREATE TABLE remote_host_promotions (
    attempt BLOB PRIMARY KEY NOT NULL CHECK (length(attempt) = 16),
    host_id BLOB NOT NULL REFERENCES remote_hosts(id) ON DELETE CASCADE,
    -- The host admin who began it (users.id).
    person TEXT NOT NULL CHECK (length(person) BETWEEN 1 AND 64),
    -- The way in, and the account whose password it checks (B9: sudo and
    -- doas check the person's account; su checks root's).
    method TEXT NOT NULL CHECK (method IN ('sudo-nopasswd', 'sudo', 'doas', 'su')),
    account TEXT NOT NULL CHECK (account IN ('person', 'root')),
    -- The rootless identity this promotion is bound to (R7).
    from_uid INTEGER NOT NULL CHECK (from_uid BETWEEN 1 AND 4294967295),
    from_fingerprint BLOB NOT NULL CHECK (length(from_fingerprint) = 32),
    link_generation BLOB NOT NULL CHECK (length(link_generation) = 16),
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN (
        'open', 'elevating', 'installing', 'enrolled', 'handed_over',
        'wrong', 'failed', 'rolled_back', 'abandoned'
    )),
    -- 1 once a password was handed to PAM for this row (B2: a timeout or
    -- failure after typing counts as a try, because PAM may have counted it).
    tried INTEGER NOT NULL DEFAULT 0 CHECK (tried IN (0, 1)),
    -- 1 once root was reached (the password was right). The 2-try count
    -- starts again after such a row.
    rooted INTEGER NOT NULL DEFAULT 0 CHECK (rooted IN (0, 1)),
    -- The successor's one-use join token (hashed) and the staged key it is bound to.
    token_digest BLOB UNIQUE CHECK (token_digest IS NULL OR length(token_digest) = 32),
    expected_key_digest BLOB CHECK (expected_key_digest IS NULL OR length(expected_key_digest) = 32),
    -- The successor's certificate and key, set at redemption.
    successor_fingerprint BLOB UNIQUE CHECK (successor_fingerprint IS NULL OR length(successor_fingerprint) = 32),
    successor_key BLOB CHECK (successor_key IS NULL OR length(successor_key) = 32),
    started_at INTEGER NOT NULL CHECK (started_at >= 0),
    -- The whole promotion's deadline; the sweeper abandons a live row after it.
    expires_at INTEGER NOT NULL CHECK (expires_at > started_at AND expires_at - started_at <= 1800),
    ended_at INTEGER CHECK (ended_at IS NULL OR ended_at >= started_at),
    cleanup TEXT NOT NULL DEFAULT 'none' CHECK (cleanup IN ('none', 'uninstall', 'retire', 'done')),
    CHECK (method != 'su' OR account = 'root'),
    CHECK (method = 'su' OR account = 'person'),
    CHECK (state NOT IN ('enrolled', 'handed_over') OR successor_fingerprint IS NOT NULL),
    CHECK (cleanup != 'retire' OR state = 'handed_over'),
    CHECK (cleanup != 'uninstall' OR (state = 'abandoned' AND successor_fingerprint IS NOT NULL)),
    CHECK (state NOT IN ('installing', 'enrolled', 'handed_over', 'rolled_back') OR rooted = 1)
) STRICT;

-- At most one live promotion per host: two tabs or two admins can't run two.
CREATE UNIQUE INDEX remote_host_promotions_live
ON remote_host_promotions(host_id)
WHERE state IN ('open', 'elevating', 'installing', 'enrolled');

-- The 2-try rule reads a host's recent tries per account.
CREATE INDEX remote_host_promotions_tries ON remote_host_promotions(host_id, account, started_at);

-- Pending outbox entries are found per host when it connects.
CREATE INDEX remote_host_promotions_cleanup ON remote_host_promotions(host_id) WHERE cleanup IN ('uninstall', 'retire');

-- A row only moves forward: from a live state to a later one or to an ending,
-- never back, and never out of an ending (apart from its outbox column).
CREATE TRIGGER remote_host_promotions_forward
BEFORE UPDATE OF state ON remote_host_promotions
WHEN NEW.state IS NOT OLD.state AND NOT (
       (OLD.state = 'open' AND NEW.state IN ('elevating', 'failed', 'abandoned'))
    OR (OLD.state = 'elevating' AND NEW.state IN ('installing', 'wrong', 'failed', 'abandoned'))
    OR (OLD.state = 'installing' AND NEW.state IN ('enrolled', 'rolled_back', 'abandoned'))
    OR (OLD.state = 'enrolled' AND NEW.state IN ('handed_over', 'abandoned'))
)
BEGIN
    SELECT RAISE(ABORT, 'promotion state only moves forward');
END;

-- The binding columns are written once, at insert (R7), and the successor's
-- identity once, at redemption.
CREATE TRIGGER remote_host_promotions_bound
BEFORE UPDATE OF attempt, host_id, person, method, account, from_uid, from_fingerprint,
    link_generation, started_at, expires_at, successor_fingerprint, successor_key
ON remote_host_promotions
WHEN NEW.attempt IS NOT OLD.attempt OR NEW.host_id IS NOT OLD.host_id
    OR NEW.person IS NOT OLD.person OR NEW.method IS NOT OLD.method
    OR NEW.account IS NOT OLD.account OR NEW.from_uid IS NOT OLD.from_uid
    OR NEW.from_fingerprint IS NOT OLD.from_fingerprint
    OR NEW.link_generation IS NOT OLD.link_generation
    OR NEW.started_at IS NOT OLD.started_at OR NEW.expires_at IS NOT OLD.expires_at
    OR (OLD.successor_fingerprint IS NOT NULL AND NEW.successor_fingerprint IS NOT OLD.successor_fingerprint)
    OR (OLD.successor_key IS NOT NULL AND NEW.successor_key IS NOT OLD.successor_key)
BEGIN
    SELECT RAISE(ABORT, 'promotion binding is write-once');
END;

-- R3: a host's mode and uid are write-once, except for exactly one change:
-- rootless to root (uid 0), from the uid an `enrolled` promotion recorded.
-- The handover transaction makes this UPDATE before it moves that row to
-- `handed_over`; every other path that tries to change mode or uid aborts.
CREATE TRIGGER remote_hosts_mode_write_once
BEFORE UPDATE OF mode, execution_uid ON remote_hosts
WHEN (NEW.mode IS NOT OLD.mode OR NEW.execution_uid IS NOT OLD.execution_uid)
    AND NOT (
        OLD.mode = 'rootless' AND NEW.mode = 'rootful' AND NEW.execution_uid = 0
        AND OLD.revoked_at IS NULL
        AND EXISTS (SELECT 1 FROM remote_host_promotions p
                    WHERE p.host_id = OLD.id AND p.state = 'enrolled'
                    AND p.from_uid = OLD.execution_uid)
    )
BEGIN
    SELECT RAISE(ABORT, 'remote host mode changes only through an enrolled promotion');
END;
