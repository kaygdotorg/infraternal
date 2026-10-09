-- Persist per-host role/plugin switches without starting or creating roles [198,201].
CREATE TABLE plugin_settings (
    role TEXT NOT NULL,
    plugin TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    PRIMARY KEY (role, plugin)
) WITHOUT ROWID;
