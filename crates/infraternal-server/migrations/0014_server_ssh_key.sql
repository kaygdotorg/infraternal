-- Retains the dedicated D183 public SSH identity and administrator-wrapped ciphertext; plaintext never belongs in SQLite.
-- Version 0013 belongs to #78's already committed remote session binding.
-- The singleton prevents concurrent starts from replacing an established identity.
CREATE TABLE server_ssh_key (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    envelope BLOB NOT NULL CHECK (length(envelope) BETWEEN 1 AND 65536)
);
