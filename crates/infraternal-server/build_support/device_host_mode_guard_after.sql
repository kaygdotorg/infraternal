-- The rewritten schema is loaded. Read storage classes from the table records
-- themselves. A covering index can still reflect the pre-rewrite layout.
CREATE TEMP TABLE device_host_mode_storage_guard (
    hosts_match INTEGER NOT NULL CONSTRAINT remote_hosts_storage_classes CHECK (hosts_match = 1),
    tokens_match INTEGER NOT NULL CONSTRAINT remote_join_tokens_storage_classes CHECK (tokens_match = 1),
    order_matches INTEGER NOT NULL CONSTRAINT device_host_mode_column_order CHECK (order_matches = 1)
);
INSERT INTO device_host_mode_storage_guard VALUES (
    NOT EXISTS (
        SELECT 1 FROM remote_hosts NOT INDEXED
        WHERE typeof(id) != 'blob'
           OR typeof(owner_id) != 'text'
           OR typeof(mode) != 'text'
           OR typeof(execution_uid) NOT IN ('integer', 'null')
           OR typeof(created_at) != 'integer'
           OR typeof(revoked_at) NOT IN ('integer', 'null')
           OR typeof(hostname) NOT IN ('text', 'null')
           OR typeof(reported_os) NOT IN ('text', 'null')
           OR typeof(device_approved) != 'integer'
           OR typeof(device_os) NOT IN ('text', 'null')
    ),
    NOT EXISTS (
        SELECT 1 FROM remote_join_tokens NOT INDEXED
        WHERE typeof(host_id) != 'blob'
           OR typeof(mode) != 'text'
           OR typeof(digest) != 'blob'
           OR typeof(issued_at) != 'integer'
           OR typeof(expires_at) != 'integer'
           OR typeof(consumed_at) NOT IN ('integer', 'null')
           OR typeof(expected_key_digest) NOT IN ('blob', 'null')
           OR typeof(key_algorithm) != 'text'
    ),
    -- Compare sizes and each ordinal, including for empty tables and when a
    -- swap involves columns with the same allowed storage classes.
    (SELECT count(*) FROM device_host_mode_original_columns) =
        (SELECT count(*) FROM pragma_table_info('remote_hosts')) +
        (SELECT count(*) FROM pragma_table_info('remote_join_tokens'))
    AND NOT EXISTS (
        SELECT table_name, position, name FROM device_host_mode_original_columns
        EXCEPT
        SELECT * FROM (
            SELECT 'remote_hosts', cid, name FROM pragma_table_info('remote_hosts')
            UNION ALL
            SELECT 'remote_join_tokens', cid, name FROM pragma_table_info('remote_join_tokens')
        )
    )
);
DROP TABLE device_host_mode_storage_guard;
DROP TABLE device_host_mode_original_columns;
