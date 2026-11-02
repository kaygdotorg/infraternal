-- Persist the server's maximum observed time for expiry across restarts (#269).
ALTER TABLE server_settings ADD COLUMN api_key_time_high_water INTEGER NOT NULL DEFAULT 0;
UPDATE server_settings SET api_key_time_high_water=unixepoch();
