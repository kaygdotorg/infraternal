<!-- Migration workflow and synthetic prod-schema fixture guide (#514, D347). -->
# Server SQLite Migrations

## Creating a migration (D347)

Always create new migrations with the helper:

```bash
scripts/new-migration add_something
```

This writes `crates/infraternal-server/migrations/YYYYMMDDHHMMSS_add_something.sql`
in UTC. Never hand-pick a sequential number, and never edit or rename a
migration that has already been applied.

## Testing migrations against the prod-schema fixture

> **Owner rule (2026-11-25):** Jobs must **never** copy production's database
> for migration checks. Use the checked-in synthetic fixture instead.

The repository checks in a deterministic SQLite fixture at
`crates/infraternal-server/tests/fixtures/prod-schema.sqlite`, built by
`scripts/build-migration-fixture.py` at the current release's last migration.
It contains **only made-up data** (synthetic user/host names, RFC 5737 / RFC 3849
documentation IP ranges, `.example.test` hostnames, and deterministic synthetic
keys) and populates every application table, constraint, index, and trigger:

- multiple accounts and host owners (1 server owner + additional host owners and
  CA administrators);
- hosts in every current mode (`rootful` and `rootless`, with room reserved in
  the generator for `device` mode once that migration lands);
- certificates of both key algorithms (`ed25519` and `p256`), active, revoked,
  and `successor`;
- join tokens (consumed and unconsumed, `ed25519` and `p256`);
- identity rotation rows (`complete`, `challenged`, `issued` with both 32-byte
  and 65-byte keys), certificate recovery rows, and all five mesh key rotation
  phases;
- sessions, terminal sessions (local and remote, open and closed), WebSocket
  connections, writers, canvas state, API keys/audits, and mesh peers, grants,
  roles, tags, and subnet routes (approved and unapproved).

### How a job uses the fixture when adding a migration

1. Add your migration file with `scripts/new-migration <name>`. Do **not**
   regenerate `prod-schema.sqlite` in the feature branch — keeping the fixture
   at the previous release's schema ensures your new migration is tested as a
   real pending upgrade.
2. Run the fixture test:
   ```bash
   cargo test -p infraternal-server --test prod_schema_migration_fixture
   ```
   and the fast Python check (also wired into `scripts/verify iterate` and
   `scripts/verify fast` as the `migration fixture` row):
   ```bash
   python3 scripts/build-migration-fixture.py --check
   ```
3. The Rust test copies `prod-schema.sqlite`, applies every pending migration
   twice (for idempotency), checks `PRAGMA integrity_check`,
   `PRAGMA foreign_key_check`, `_sqlx_migrations` checksums, per-table row
   counts, byte-for-byte preservation across all kept columns, D379 rusqlite
   runner compatibility, and live constraints/triggers.
4. If your migration **intentionally** prunes, merges, or rewrites rows in an
   existing table, add that table's name to `TRANSFORMED_TABLES` in
   `crates/infraternal-server/tests/prod_schema_migration_fixture.rs` and add a
   targeted test asserting the new contents.

### How to refresh the fixture after a release adds migrations

When a release ships new migrations:

1. Update `seed_synthetic_data()` in `scripts/build-migration-fixture.py` to
   populate any new tables, columns, or modes (for example, adding a synthetic
   `device`-mode host once `remote_hosts.mode` accepts `'device'`). Keep all
   data synthetic and deterministic (no wall-clock `unixepoch()` values left
   unnormalized, no real names, keys, or addresses).
2. Regenerate the checked-in fixture:
   ```bash
   python3 scripts/build-migration-fixture.py
   ```
3. Clear any table names from `TRANSFORMED_TABLES` in
   `crates/infraternal-server/tests/prod_schema_migration_fixture.rs` that are
   now part of the refreshed baseline, and add coverage assertions in
   `assert_fixture_coverage()` for any new table/mode.
4. Verify determinism and tests:
   ```bash
   python3 scripts/build-migration-fixture.py --check
   cargo test -p infraternal-server --test prod_schema_migration_fixture
   ```
