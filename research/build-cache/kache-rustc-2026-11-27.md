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

## Static x86_64 comparison

Both builds passed and produced the same 34,032,888-byte stripped static
PIE with no ELF interpreter. SHA-256 is
`ac2bcb3d7e2ec39f0db9b1ae7ea74ad7300111687b5a3359c0f7bb69d0b01456`.
The wrapped run's generated OpenSSL Makefile named the repository's
`.cargo/musl-cc-avx512.sh` as its compiler, and the target contained zero
`.kache-real` files.

| Mode | Wall s | Cargo user/sys CPU s | Daemon user/sys CPU s | Peak target bytes | Peak cache bytes | Peak combined bytes | Load 1m min/median/max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Control | 1,454.352 | 2,717.928 / 240.246 | — | 2,288,332,800 | — | 2,288,332,800 | 12.15 / 21.66 / 36.79 |
| Cold kache | 1,854.788 | 3,014.213 / 276.480 | 19.49 / 22.37 | 2,288,312,320 | 1,336,188,928 | 3,624,501,248 | 17.05 / 27.46 / 48.68 |

Kache recorded 0 local hits, 548 misses and 0 duplicate compiles.
Wall time increased 27.5% in this serial comparison. Median one-minute
host load also rose, from 21.66 to 27.46. Total measured CPU including
the daemon rose 12.7%. These are single draws on a shared host.

## Static aarch64 comparison

The aarch64 build uses the same per-arm target directories as the x86_64
build, so Cargo can keep host-side build tools and the already staged Zig.
The architecture-specific output starts cold. Target totals include the
x86_64 outputs retained from the previous phase.

Both builds produced the same 30,250,912-byte stripped static ELF with no
ELF interpreter. SHA-256 is
`1174cd826ba0a81900ad8b23a4dbdbe183ce590e4127fc1d12501608766ee767`.

| Mode | Wall s | Cargo user/sys CPU s | Daemon user/sys CPU s | Peak target bytes | Peak cache bytes | Peak combined bytes | Load 1m min/median/max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Control | 1,640.010 | 2,804.749 / 204.039 | — | 3,842,617,344 | — | 3,842,617,344 | 13.08 / 24.80 / 50.74 |
| Kache | 1,353.158 | 2,638.676 / 190.101 | 10.59 / 12.13 | 3,724,115,968 | 2,331,275,264 | 6,055,391,232 | 11.66 / 24.43 / 39.51 |

The aarch64 wrapper logged 0 local hits, 357 misses and 0 duplicate
compiles. Wall time fell 17.5% and measured CPU including the daemon
fell 5.2%. Across both static builds, wall rose from 3,094.362 s to
3,207.946 s and total CPU rose from 5,966.962 s to 6,184.049 s.
The retained x86_64 cache is included in the aarch64 wrapped disk total.

The harness initially rejected the aarch64 wording `statically linked`
after Cargo had already exited successfully. I checked the saved artifact
with `readelf -lW`, updated the check to accept both static ELF forms, and
retained the original control timing.

[Static build evidence](https://git.kayg.org/kayg/infraternal/issues/608#issuecomment-107167)

## Workspace test comparison

Both `--no-run` builds passed. The wrapped store already contained the
static build outputs. The first native test build in each target was cold.
Target totals include the two static profiles retained from earlier phases.

| Mode | Wall s | Cargo user/sys CPU s | Daemon user/sys CPU s | Peak target bytes | Peak cache bytes | Peak combined bytes | Load 1m min/median/max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Control | 906.072 | 2,632.056 / 328.899 | — | 14,404,661,248 | — | 14,404,661,248 | 12.93 / 23.65 / 44.30 |
| Kache | 897.378 | 2,763.679 / 367.321 | 42.28 / 57.93 | 14,404,747,264 | 12,554,342,400 | 26,959,089,664 | 14.57 / 20.56 / 27.11 |

Kache recorded 0 local hits, 776 misses and 0 duplicate compiles. Wall
time fell 1.0% and measured CPU including the daemon rose 9.1%. The
registered store briefly reached 12,492,117,765 bytes against an 8 GiB
configured budget. The home volume fell below the host's shared 25 GiB
build-slot floor. Collecting only the private cache at a 5 GiB cap left
4,814,858,154 registered bytes and about 29.9 GiB free. Any subsequent
warm comparison starts from that reduced store, with the 5 GiB cap.

The first runtime fixture used `unshare --map-current-user`. It preserved
the invoking UID, but the unmapped host root UID appeared as 65534 on
`/home` and `/mnt/build`. Trusted-path and permission-sensitive tests
therefore failed even in the control. Those results cannot qualify the
wrapper. A preflight verified a temporary loopback-only network and mount
namespace that retains the original UID mapping. Its launcher drops to
the build account before executing any checkout code and mounts a
private `/run` to isolate the host system bus. The invalid runtimes
were stopped by their own recorded process IDs. Their statuses serve
as fixture diagnostics.

[Test-build and fixture evidence](https://git.kayg.org/kayg/infraternal/issues/608#issuecomment-107336)

## Cache sharing boundary

Jobs under the same Unix account can share a compiler store and daemon
while keeping independent Cargo targets. Use a shared store only for
jobs trusted to write one another's executable compiler outputs.
The job's directory mode and a Kache trust-domain label address accidental
overlap under a shared UID. Separate Unix identities provide the write
boundary for different trust domains. This trial uses a dedicated store,
socket, configuration and XDG cache root. It leaves shared hardlink restores
off, so test and build targets do not share mutable inodes through the cache.

The trial's cache lives on the home volume and the target lives on
`/mnt/build`. Cross-volume restores copy bytes. The 8 GiB blob limit
covers cache blobs. The allocated footprint also includes bookkeeping
and logs. Use measured free space and allocation for capacity planning
alongside the configured blob limit.

These runs exercise Cargo inside `nix develop`. The [J1306 notes](kache-2026-11-27.md#nix-package-builds)
describe the separate sandboxed Nix release package.
[Upstream storage and sharing settings](https://ninja.kunobi.com/docs/kache/getting-started/configuration)
