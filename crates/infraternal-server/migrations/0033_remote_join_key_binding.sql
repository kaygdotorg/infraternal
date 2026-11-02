-- Invitations created before key binding remain readable but fail closed at redemption.
ALTER TABLE remote_join_tokens
ADD COLUMN expected_key_digest BLOB
CHECK (expected_key_digest IS NULL OR length(expected_key_digest) = 32);
