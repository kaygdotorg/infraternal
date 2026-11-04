-- D336: a per-action tap is bound to the one action shown on screen. A sign-in or
-- re-authentication ceremony may name one action; its session row keeps a digest of that
-- action and its parameters. NULL (every existing session and every plain sign-in) authorizes
-- no per-action change. `tap_spent` (0045) still makes the tap single use.
ALTER TABLE sessions ADD COLUMN tap_action TEXT;
