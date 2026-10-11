-- Records explicit administrator membership generations; no signing secret or CA envelope enters SQLite [168], #78.
CREATE TABLE ca_administrators (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(generation > 0),
    active INTEGER NOT NULL CHECK(active IN (0, 1))
);

-- Existing installation owners seed the explicit administrator role once.
-- Subsequent authorization reads this membership, never the owner flag.
INSERT INTO ca_administrators(user_id, generation, active)
SELECT id, 1, 1 FROM users WHERE owner = 1;

-- Initial owner enrollment may happen after all migrations have run. This
-- bootstrap trigger grants the role once; it does not mirror later owner edits.
CREATE TRIGGER ca_administrator_on_initial_owner
AFTER INSERT ON users WHEN NEW.owner = 1
BEGIN
    INSERT INTO ca_administrators(user_id, generation, active)
    VALUES(NEW.id, 1, 1);
END;
