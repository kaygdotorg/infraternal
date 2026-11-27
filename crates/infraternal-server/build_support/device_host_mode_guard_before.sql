-- Remember column names by storage position while the old schema is still loaded.
-- Checking names after the rewrite alone only checks the newly supplied text.
CREATE TEMP TABLE device_host_mode_original_columns (
    table_name TEXT NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    PRIMARY KEY (table_name, position)
);
INSERT INTO device_host_mode_original_columns
SELECT 'remote_hosts', cid, name FROM pragma_table_info('remote_hosts')
UNION ALL
SELECT 'remote_join_tokens', cid, name FROM pragma_table_info('remote_join_tokens');
