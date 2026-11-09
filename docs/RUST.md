<!-- Rust workspace and static-build notes. -->
# Rust workspace and static builds

The workspace pins Rust 1.99.1 with rustfmt, Clippy, and the x86_64 and aarch64
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

## Cross-host reproducibility boundary (#296, J81)

The source audit and measurements in this section use the original Rust 1.99.0
toolchain. They remain the recorded baseline when the current patch pin advances.

The pinned Cargo cannot provide host-independent crate identities through its
supported build flags. This is a limitation of the current recipe, not a claim
that reproducible cross-compilation is fundamentally impossible. Achieving byte
equality requires changing Cargo's identity algorithm or replacing the identities
in a compiler driver, with a separately reviewed disambiguation policy. Building
with one compiler host architecture on both machines is another possible route;
it does not establish equality between native compilers of different host
architectures. J81 does not introduce a patched Cargo or an emulator.

The exact source is Cargo 1.99.0, commit
`5f94df4789f005f9a352888e8355ffc645b7ed0e`, in
[`src/compiler/build_runner/compilation_files.rs`](https://github.com/rust-lang/cargo/blob/5f94df4789f005f9a352888e8355ffc645b7ed0e/src/compiler/build_runner/compilation_files.rs):

1. `hash_rustc_version` includes the `host:` line from `rustc -vV` for
   `CompileKind::Host`. Build scripts and procedural macros are host units even
   when the application has an explicit musl target.
2. `compute_metadata` recursively hashes **all** dependency `c_metadata` values
   into the target unit's `c_metadata`, including its build-script dependency.
   It does not substitute the build script's stdout or generated-file contents.
   Identical build-script output therefore does not imply identical target
   identity.
3. Cargo supplies that identity as `-C metadata=...`. The compiler uses it for
   symbol disambiguation and LLVM module identities before LTO. Stripping the
   final ELF cannot undo the code and layout choices made from those inputs.

Adding a fixed `-C metadata` through `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
target rustflags or `cargo rustc --` does **not** replace Cargo's value.
Rust 1.99.0 defines `metadata` as `Vec<String>` with `parse_list`, which appends
each supplied value. See
[`compiler/rustc_session/src/options.rs`](https://github.com/rust-lang/rust/blob/b940084d7/compiler/rustc_session/src/options.rs).
`__CARGO_DEFAULT_LIB_METADATA` also only adds a hash input. None removes the
host dependency identity. A driver that strips Cargo's value would be a new
identity recipe: using only a constant, package name or version would discard
the source, features, profile and dependency distinctions Cargo deliberately
preserves. J81 does not silently weaken those distinctions.

The other proposed controls operate after, or independently of, this hash:

| Control | Why it cannot remove this input |
| --- | --- |
| `--remap-path-prefix` | Rewrites source paths; Cargo deliberately excludes path-bearing rustflags from `c_metadata`. It does not rewrite the host version line. |
| `SOURCE_DATE_EPOCH` | Configured as `0`; Cargo's identity input is the compiler host, not the build time. |
| Zig target flags | Already explicit for each shipping target. The control below has no C or Zig dependency. |
| Build-script host detection | A script that emits identical output still has a host identity in Cargo's dependency graph. |

For an isolated control, build a dependency-free `#![no_std]` library exporting
`#[inline(never)] pub fn result() -> u8 { 42 }` with `cargo rustc --release
--lib --target TARGET -- --emit=llvm-ir`. Compare the IR on both hosts, first
without a build script, then with a script whose only statement is
`println!("cargo:rerun-if-changed=build.rs")`, then append
`-Cmetadata=j81-fixed` to the target compiler arguments. The explicit target,
source, toolchain and script output are identical. This isolates the identity
input without native archives, application dependencies or LTO.

The controlled IR comparisons passed on both targets as follows. The last two
rows are expected mismatches, not passing reproducibility claims:

| Control | x86_64 IR identical | aarch64 IR identical |
| --- | --- | --- |
| No build script | yes | yes |
| No-op build script | no | no |
| No-op script plus `-Cmetadata=j81-fixed` | no | no |

For example, the x86 `result` symbol with the no-op script is
`_RNvCs556cgIFhxcV_13repro_control6result` on compute01 and
`_RNvCslHMVKE8lLAg_13repro_control6result` on dev-02. Without the script,
both hosts produce `_RNvCscOT2bMIOWac_13repro_control6result` and the entire
IR file has SHA-256
`0b98933ebd2b99927466796caf4c448809b7b51f0293e23b8a098dc07a183fbc`.
The aarch64 no-script IR also matches, with SHA-256
`4f5df7b31c80bf76966c02df9edcaa72472211972d1e34cdac069de9275238b6`.

Both hosts built the same Rust source baseline,
`ad2b2c04666ca466107e80288ed47c5980c9a7ce`, through `scripts/static-cargo`
inside the pinned Nix development shell, with `CARGO_BUILD_JOBS=3`, the same
checkout path `/home/claude/worktrees/j81`, and one target directory per host.
Rust is 1.99.0 (`b940084d7`), LLVM 23.1.1 and Zig 0.15.2. The final
documentation-only commit and its same-commit rebuild receipts are recorded on
issue #296; there is no production source or build-configuration delta.

| Build host | Shipping target | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| compute01 (x86_64) | x86_64 | 21,729,392 | `94b5b4d210213a990ca43b146c9d65fec983181c75ec2d6b6a969fd8108956e1` |
| dev-02 (aarch64) | x86_64 | 21,732,208 | `19d80905d835af9d8ca386bccb33a158b8c4ee59d8479c827a451f39a0887091` |
| compute01 (x86_64) | aarch64 | 19,855,816 | `69411ccaab083267b68e7d6d160abc682044fdd52611a6dea321c5b048934a75` |
| dev-02 (aarch64) | aarch64 | 19,856,104 | `e4259d9284f6e54ff8c9586f5d8c3e36a297c0aeed88a8650b4f1b6daf410398` |

The current cross-host deltas are +2,816 bytes for x86 and +288 bytes for
aarch64, measured as dev-02 minus compute01. For x86, `.text` grows by 2,752
bytes, `.gcc_except_table` by 52, `.eh_frame_hdr` by 8 and `.eh_frame` by 88;
section alignment also changes, so those deltas do not sum to the file delta.
The `.rodata` size is identical but its contents differ. The scanned checkout,
Nix store, target, Rustup and Cargo path prefixes are absent from the x86
shipping images. This is already a difference in compiler inputs and allocated
ELF sections; neither stripping more metadata nor changing timestamps repairs it.

The next toolchain investigation would separate Cargo's host cache identity
from target symbol identity while retaining package source, version, features,
profile and dependency distinctions. That requires a Cargo change or a reviewed
replacement identity recipe, not another additive target flag. J81 leaves that
choice open and makes no cross-host byte-equality claim.
