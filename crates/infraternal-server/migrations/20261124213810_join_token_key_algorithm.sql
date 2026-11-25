-- join token key algorithm (#580, client-core plan §7 P3).
--
-- An invitation binds the digest of the one key that may redeem it
-- (`expected_key_digest`). It now also names that key's algorithm, so a join
-- can only ever produce a certificate of the algorithm the approval allowed:
--
-- - `ed25519`: every Add-host invitation, every `system`/`user` machine join
--   and every row written before #580 (the default).
-- - `p256`: only a `device` machine join (owner question Q4 on #580), which the
--   server does not yet accept outside tests (plan step P5 turns it on).
--
-- Redemption compares this column with the CSR's algorithm in the same write
-- that spends the invitation. Adding a column with a constant default and a
-- CHECK needs no rebuild; every existing row satisfies the CHECK.
ALTER TABLE remote_join_tokens
    ADD COLUMN key_algorithm TEXT NOT NULL DEFAULT 'ed25519'
    CHECK (key_algorithm IN ('ed25519', 'p256'));
