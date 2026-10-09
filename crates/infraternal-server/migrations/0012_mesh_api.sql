-- Mesh inventory, named grants, action roles, revisions, and audit evidence [154,163,164,187].
CREATE TABLE mesh_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0)
);
INSERT INTO mesh_state(singleton, revision) VALUES (1, 0);

CREATE TABLE mesh_nodes (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    public_key BLOB NOT NULL UNIQUE CHECK (length(public_key) = 32),
    last_seen BIGINT,
    last_rtt_us BIGINT CHECK (last_rtt_us IS NULL OR last_rtt_us >= 0)
);
CREATE INDEX mesh_nodes_seen ON mesh_nodes(last_seen, id);

CREATE TABLE mesh_tags (
    name TEXT PRIMARY KEY COLLATE BINARY,
    created_at BIGINT NOT NULL
);

CREATE TABLE mesh_tag_members (
    tag_name TEXT NOT NULL REFERENCES mesh_tags(name) ON UPDATE CASCADE ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES mesh_nodes(id) ON DELETE CASCADE,
    PRIMARY KEY(tag_name, node_id)
) WITHOUT ROWID;
CREATE INDEX mesh_tag_members_node ON mesh_tag_members(node_id, tag_name);

CREATE TABLE mesh_grants (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE BINARY,
    from_kind TEXT NOT NULL CHECK (from_kind IN ('node', 'tag')),
    from_value TEXT NOT NULL,
    to_kind TEXT NOT NULL CHECK (to_kind IN ('node', 'tag')),
    to_value TEXT NOT NULL,
    both_ways INTEGER NOT NULL CHECK (both_ways IN (0, 1)),
    ports_json TEXT NOT NULL
);
CREATE INDEX mesh_grants_from ON mesh_grants(from_kind, from_value);
CREATE INDEX mesh_grants_to ON mesh_grants(to_kind, to_value);

CREATE TABLE mesh_roles (
    name TEXT PRIMARY KEY COLLATE BINARY,
    created_at BIGINT NOT NULL
);
CREATE TABLE mesh_role_actions (
    role_name TEXT NOT NULL REFERENCES mesh_roles(name) ON UPDATE CASCADE ON DELETE CASCADE,
    action TEXT NOT NULL,
    scope_tag TEXT REFERENCES mesh_tags(name) ON UPDATE CASCADE ON DELETE CASCADE,
    PRIMARY KEY(role_name, action, scope_tag)
);
CREATE UNIQUE INDEX mesh_role_actions_global ON mesh_role_actions(role_name, action)
    WHERE scope_tag IS NULL;
CREATE INDEX mesh_role_actions_lookup ON mesh_role_actions(action, scope_tag, role_name);
CREATE TABLE mesh_user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL REFERENCES mesh_roles(name) ON UPDATE CASCADE ON DELETE CASCADE,
    PRIMARY KEY(user_id, role_name)
) WITHOUT ROWID;
CREATE INDEX mesh_user_roles_role ON mesh_user_roles(role_name, user_id);

CREATE TABLE mesh_audit (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    revision INTEGER NOT NULL,
    occurred_at BIGINT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE INDEX mesh_audit_actor ON mesh_audit(user_id, id);
