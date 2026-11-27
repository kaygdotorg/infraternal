# Rust-only compiler-cache trial on compute01, 2026-11-27

[J1322, issue #608](https://git.kayg.org/kayg/infraternal/issues/608) follows
the [J1306 native compiler compatibility stop](kache-2026-11-27.md).

## Keeping the wrapper on Rust

The pinned cc 1.11.3 looks at the file stem in `RUSTC_WRAPPER`.
It recognizes `kache` and puts it in front of the native compiler driver.
For this trial, `RUSTC_WRAPPER` points to `kache-rustc`, a private symlink
to the pinned kache 2.4.0 release executable. That stem falls outside
cc's allowlist. Cargo still calls kache for rustc. The trial uses regular
Cargo, the repository's pinned Zig C drivers, a private install prefix and
cache, and no login service or compiler shims. The Linux musl release
archive was verified against GitHub's asset SHA-256
`6dc5feb2fdcc982538869bc0d0f63ad0da2c8f1a2c22649e7707ff4eb4dbaab7`.
[Pinned cc source](https://docs.rs/crate/cc/1.11.3/source/src/lib.rs),
[kache 2.4.0 release](https://github.com/kunobi-ninja/kache/releases/tag/v2.4.0)

## Comparison

The initial pin is `857b2003c85310940e66ccb5a60ea250f139b5fd`,
the tip of dev at job start. The control and wrapped phases use the
same source directory and separate fresh Cargo targets. All builds run in
one build slot at a time on compute01, with four Cargo jobs and Cargo
incremental compilation off. Queue time stays outside build timings.
The pinned toolchain and dependencies are already downloaded. The wrapped
phase starts with an empty private cache. Its 8 GiB limit applies to cache
blobs. Target seeding, incremental seeding, shared hardlink restores,
empty OUT_DIR aliasing and build-script output replay are off. Kache
2.4.0 normally installs build-script launchers even with hermetic mode
off. The first wrapped attempt produced 34 `.kache-real` files before
it was stopped. Setting `KACHE_BUILD_SCRIPT_CACHE=0` disables the
launchers. The retry uses a fresh target and compiler store. Cargo
compiles the build scripts through the Rust wrapper and executes their
original binaries.
[Pinned build-script launcher source](https://github.com/kunobi-ninja/kache/blob/v2.4.0/src/build_script.rs#L79-L82)

The static build uses `scripts/static-cargo build --locked --release
--package infraternal --target <target>`. Each isolated target gets its
pinned Zig installation from `scripts/auth-toolchain` and a native driver
version check before timing. The first preflight omitted that installation
and OpenSSL's Zig invocation exited 127, causing Cargo to exit 101. The
timed comparison starts again with a fresh target after staging Zig.
A same-revision hash mismatch or
different test outcome stops the experiment. The workspace test build
uses `cargo test --locked --workspace --no-fail-fast --no-run`.
The test execution has only a loopback interface, uses the invoking UID
and a private `/run`, and inherits a private short fixture state root.
The full test run has the same 5,400 s hang bound as the workspace test
row in the gate.

Shell wall and child CPU timing cover Cargo and its descendants. Private
daemon CPU is sampled separately from procfs. Disk samples count allocated
bytes across the target, blob cache and private diagnostic cache on a
30-second interval and at phase exit. Peaks are sampled lower bounds.
Load averages describe the shared build host. The cache and target are on
separate filesystems, so this trial measures cross-filesystem copies.

## Static x86_64 control

The wrapper-free build passed and produced a 34,032,888-byte stripped
static PIE with no ELF interpreter. Its SHA-256 is
`ac2bcb3d7e2ec39f0db9b1ae7ea74ad7300111687b5a3359c0f7bb69d0b01456`.
Wall time was 1,454.352 s, user CPU was 2,717.928 s, and system CPU
was 240.246 s. The target peaked at 2,288,332,800 allocated bytes
across 49 samples. One-minute host load ranged from 12.15 to 36.79,
with median 21.66.
