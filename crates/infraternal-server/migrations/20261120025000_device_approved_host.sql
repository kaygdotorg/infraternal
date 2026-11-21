-- Keep the installer origin after the passkey approval expires. Before this
-- column, only device-approved invitations used a 600-second receipt.
ALTER TABLE remote_hosts
    ADD COLUMN device_approved INTEGER NOT NULL DEFAULT 0 CHECK (device_approved IN (0, 1));

-- Keep the device-reported platform so offline removal can give the Mac command.
ALTER TABLE remote_hosts
    ADD COLUMN device_os TEXT CHECK (device_os IS NULL OR length(device_os) BETWEEN 1 AND 256);

UPDATE remote_hosts
SET device_approved = 1
WHERE EXISTS (
    SELECT 1 FROM remote_join_tokens t
    WHERE t.host_id = remote_hosts.id
      AND t.expires_at - t.issued_at = 600
      AND t.expected_key_digest IS NOT NULL
);
