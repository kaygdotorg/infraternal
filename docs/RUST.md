<!-- Rust workspace and static-build notes. -->
# Rust workspace and static builds

The workspace pins Rust 1.99.0 with rustfmt, Clippy, and the x86_64 and aarch64
musl standard libraries. The package manifests inherit the AGPL-3.0-only
license and workspace lint policy. The shim repeats the Clippy settings because
Cargo rejects overriding a lint while inheriting `[lints] workspace = true`; it
sets `unsafe_code` to `deny` so future PTY syscalls can add narrowly audited
unsafe blocks.

Both musl targets use `rust-lld` from the active Rust toolchain. Rust distributes
the target CRT objects with these targets, so the cross build needs neither a
host-specific C cross compiler nor a separately downloaded Zig toolchain. The
small `.cargo/rust-lld.sh` adapter resolves LLD from the pinned toolchain
and invokes it under the `ld.lld` name expected by Rust's GNU linker arguments. This keeps
the cross linker tied to the compiler version and lets the same static-build
gate run locally and in CI.

The release profile uses full LTO and one codegen unit to optimize across crate
boundaries, and `opt-level = 3` to favor runtime speed. Stripping removes debug
symbols from release artifacts. It keeps `panic = "unwind"`: the server runs
many independent session tasks, and unwinding lets tokio contain a panic to
the task that caused it. With abort, one bug would end every session.
