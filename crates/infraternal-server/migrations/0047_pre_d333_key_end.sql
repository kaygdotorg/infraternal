-- J154 P3-1 (#303, D333): keys issued before D333 have no absolute end, so sliding renewal
-- would keep them alive forever, and their approval never showed a lifetime. Each gets one
-- now. `api_keys` keeps no issue time, so the end cannot be issue time plus the policy:
-- it is the key's current deadline, or 24 hours after this upgrade if that comes sooner.
-- The upgrade time is the persisted key clock when it is ahead of the wall clock.
UPDATE api_keys
SET hard_expires_at = MIN(
    expires_at,
    MAX(unixepoch(), (SELECT api_key_time_high_water FROM server_settings WHERE id = 1)) + 86400
)
WHERE hard_expires_at IS NULL;
