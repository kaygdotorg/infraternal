<!-- Records the origin and local scope of the vendored sqlx-sqlite copy (D379, #473). -->
# sqlx-sqlite 0.8.6 on SQLite 3.54

Published sqlx-sqlite 0.8.6, registry checksum
c2d12fe70b2c1b4401038055f90f151b78208de1f9f89a7dbfd41587a10c3eea (the same
checksum origin/dev's Cargo.lock pinned). Original licensing (`LICENSE-MIT`,
`LICENSE-APACHE`) is retained.

**One local change:** in `Cargo.toml`, the `libsqlite3-sys` requirement moves
from `0.30.1` to `0.39.1`. No source file is changed. `Cargo.toml.orig` is the
upstream manifest as published.

**Why.** D379 moves the server's database from sqlx to rusqlite 0.41 in
reviewed slices. rusqlite 0.41 needs `libsqlite3-sys` 0.39, and sqlx 0.8.6
pins `^0.30.1`. Both crates declare `links = "sqlite3"`, and Cargo allows only
one of them in a dependency graph, so the two drivers could not coexist during
the port at all. With this copy, both drivers link the one bundled SQLite
3.54.1, which also fixes RUSTSEC-2026-0459.

Checked on 2026-11-09 (J449): sqlx-sqlite 0.8.6 compiles unchanged against
libsqlite3-sys 0.39.1, and the server's full test suite runs on it (see #473).

**Drop this copy** when the last sqlx use leaves the workspace (the end of the
D379 port).
