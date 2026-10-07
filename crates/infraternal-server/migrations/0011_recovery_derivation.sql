-- Separate verifier and envelope versions: upgrading authentication never relabels ciphertext [23,#45,D151].
ALTER TABLE users ADD COLUMN recovery_version INTEGER NOT NULL DEFAULT 1 CHECK(recovery_version IN (1,2));
ALTER TABLE users ADD COLUMN recovery_wrap_version INTEGER NOT NULL DEFAULT 1 CHECK(recovery_wrap_version IN (1,2));
