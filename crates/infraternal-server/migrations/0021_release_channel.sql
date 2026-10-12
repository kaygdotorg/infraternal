-- Store plugin-owned settings alongside runtime switches; descriptor defaults apply until an explicit write [198,226].
ALTER TABLE plugin_settings ADD COLUMN settings TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(settings));
