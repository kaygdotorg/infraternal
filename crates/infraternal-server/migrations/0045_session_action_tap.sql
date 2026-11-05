-- D333: a tap authorizes one per-action change (key approval, passkey and recovery-key
-- changes, security settings). Each sign-in or re-authentication is a new session with an
-- unspent tap; the change spends it in its own transaction.
ALTER TABLE sessions ADD COLUMN tap_spent INTEGER NOT NULL DEFAULT 0 CHECK (tap_spent IN (0, 1));
