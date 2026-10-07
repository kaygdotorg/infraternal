//! Track the auth migration directory so warm builds embed newly added migrations.

fn main() {
    // SQLx tracks existing migration files, but adding one must also rebuild the
    // migrate! invocation. Directory tracking keeps schema-only changes visible.
    println!("cargo:rerun-if-changed=migrations");
}
