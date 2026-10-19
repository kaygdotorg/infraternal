-- Account-owned layout references and bounded replay; receipts outlive checkpoints [180,183,248].
CREATE TABLE canvas_heads (
    account TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision >= 0),
    document TEXT NOT NULL,
    initialized INTEGER NOT NULL CHECK(initialized IN (0,1))
);
CREATE TABLE canvas_operations (
    account TEXT NOT NULL REFERENCES canvas_heads(account) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    event TEXT NOT NULL,
    PRIMARY KEY(account, revision)
);
CREATE TABLE canvas_snapshots (
    account TEXT PRIMARY KEY REFERENCES canvas_heads(account) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    document TEXT NOT NULL
);
CREATE TABLE canvas_receipts (
    account TEXT NOT NULL REFERENCES canvas_heads(account) ON DELETE CASCADE,
    op_id TEXT NOT NULL,
    request TEXT NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY(account, op_id)
);
CREATE TABLE canvas_closed (
    account TEXT NOT NULL REFERENCES canvas_heads(account) ON DELETE CASCADE,
    window_id TEXT NOT NULL,
    PRIMARY KEY(account, window_id)
);
