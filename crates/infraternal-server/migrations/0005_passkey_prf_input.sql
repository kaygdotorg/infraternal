-- Preserve legacy PRF inputs while new passkeys use user-bound inputs [23,24].
-- NULL means the original v1 constant, never an absent key-wrapping input.
ALTER TABLE passkeys ADD COLUMN prf_input TEXT;
