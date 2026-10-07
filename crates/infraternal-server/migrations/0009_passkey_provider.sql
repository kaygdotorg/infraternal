-- Diagnostic authenticator metadata only; legacy rows have no trustworthy provider [24,28; #43].
ALTER TABLE passkeys ADD COLUMN aaguid TEXT;
-- Bind the label to the credential used, rather than guessing from another passkey on the account.
ALTER TABLE sessions ADD COLUMN passkey_id TEXT;
