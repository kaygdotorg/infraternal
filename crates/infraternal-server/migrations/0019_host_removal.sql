-- Public bootstrap coordinates and durable, freshly authorized removal intents [16][168][198], #87.
-- Revocation tombstones and certificate fingerprints remain in the denial ledger.
CREATE TABLE remote_host_bootstrap (
    host_id BLOB PRIMARY KEY NOT NULL REFERENCES remote_hosts(id) ON DELETE RESTRICT,
    address TEXT NOT NULL CHECK(length(address) BETWEEN 1 AND 1024),
    trust_lookup TEXT CHECK(length(trust_lookup) BETWEEN 1 AND 512)
);
CREATE INDEX remote_host_bootstrap_lookup ON remote_host_bootstrap(trust_lookup);
CREATE TABLE remote_host_removals (
    host_id BLOB PRIMARY KEY NOT NULL REFERENCES remote_hosts(id) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    requested_at BIGINT NOT NULL CHECK(requested_at >= 0),
    uninstall INTEGER NOT NULL CHECK(uninstall IN (0,1)),
    host_cleanup TEXT NOT NULL CHECK(host_cleanup IN ('pending','requested','unreachable','retained')),
    completed_at BIGINT CHECK(completed_at >= requested_at)
);
