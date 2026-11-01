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

`verify fast` builds and inspects both musl targets on x86_64 and aarch64
Linux hosts (#296). CLI and key-memory runtime checks use the native shipping
image. The foreign key-memory check and, on aarch64, the x86-only AES-GCM
vector report `SKIP` with their native-execution requirement. An emulator's
successful memory-protection syscall is not evidence about the native kernel.

Restart tests admit the running test image through the production trust rules.
Build paths with group-writable ancestors must sit below an owner-only `0700`
directory. On dev-02, home mode `0750` above `worktrees` mode `0775` caused five
restart tests to wait after correctly refusing their current executable.
Changing home to `0700`, matching compute01, made the identical test executable
pass all 18 restart tests; no timeout or admission rule changed (#296).

Cross-host builds also change Cargo's host-built dependency identities. With
Rust 1.99.0 (`b940084d7`), LLVM 23.1.1 and Zig 0.15.2, the same `a26615c50`
sources and flags produce x86 images of 21,642,320 bytes on compute01 and
21,649,296 bytes on dev-02. For example, crossbeam-utils emits identical
build-script output, but Cargo gives its target crate different identities
(`615b1674294a9fde` and `c11c495add14c870`) through the host build-script
dependency. Those identities propagate through Rust symbols and LTO; stripping
does not make the resulting code, constant layout and unwind tables identical.
The C/VT archive differences were confined to debug sections, and neither
shipping image contained checkout, target, Cargo, Rustup or Nix store paths.
This is a compiler/dependency-identity difference, not a path leak to remove.
The existing cross-root release reproducibility test checks repeatability on
one build architecture; it does not promise equality between host architectures.
The `37bbda455` arm cross-build reproduces 21,456,976 bytes, 8,704 bytes above
the recorded native x86 build (#296). Gate portability does not change the
release profile or select a new toolchain.
