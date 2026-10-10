<!-- Records measured warm-CA continuity, limits and distribution evidence for #154 [168][217]. -->
# CA handoff verification

Runtime and tests: `5197e376`, based on production `06857458`. All measurements
ran locally on infraternal-dev under `systemd-run --user --scope -p CPUWeight=10000`.
No deployment was performed.

## Real shipping process

The test harness is a debug Rust test executable; the server and restart CLI
are the stripped x86_64 musl **release** executable. It performs 25 same-PID
replacements: staged path update/rollback, default-path restart and SIGHUP reload.
A successful new control socket generation and authenticated CA status establish
completion, rather than an acknowledgement from the old process.

| Measurement | p50 | Maximum observed |
| --- | ---: | ---: |
| Restart request to new unlocked CA status | 30.736 ms | 39.541 ms |
| New HTTP TCP connection refusal bracket | 23.795 ms | 29.478 ms |

The probe samples with a configured 1 ms sleep (scheduler resolution and host
load add uncertainty). It establishes an old-process success before restart;
last success before refusal and first success after recovery bound the outage.
If the final recovery sample is missed, the authenticated health-confirmed end
bounds recovery. These are sampled upper brackets, not exact outage edges.
212 connection failures were observed over 25 replacements. QUIC reconnect
latency and artificial WAN delay are outside this local measurement.

Scale: 10000 **retained** host records, 50 users, 128 real live PTYs (the current
single-host limit). Every original shim PID survived all replacements; all 128
sessions reattached, and new input produced the expected output after reload.
These records are not claimed as 10000 live remote connections.

Machine: Linux 6.12.111+deb13-amd64, 8 available CPUs, Intel Core i9-9900K
at 3.60 GHz. Benchmark load averages: before `5.93 13.18 15.33`, after
`6.10 12.97 15.24`. Full transcript: [shipping-release.log](shipping-release.log).

The carrier is one frame per server, independent of node/session count: at most
2090 bytes, with a 2091-byte bounded receive buffer and a 32-byte zeroized seed
serialization buffer. It is not allocated once per session or per host.

## Correctness and security

- Real same-PID exec retains an unlocked signer; a separate process with the
  same UID cannot import the anonymous channel. No reusable token exists.
- Truncated and wrong-version frames leave both unit and shipping processes
  locked. Abrupt stop during partial seed import is followed by a locked cold
  successor. Ordinary shipping cold startup remains locked.
- A non-owner process cannot connect to the private restart socket.
- Parser properties cover 4097 malformed lengths plus every valid-frame
  truncation, every byte mutation, trailing data and a different issuer.
  `fuzz/fuzz_targets/remote_ca_handoff_decode.rs` is compiled by workspace Clippy;
  the property corpus executes in the CA suite. No private frame corpus is saved.
- CA suite: 42 passed, 0 failed, 7 explicitly ignored diagnostics; remote server
  suite: 49 passed, 0 failed, 10 explicitly ignored diagnostics. The separate
  infraternal-agent remote suite passed 22 tests (2 ignored); see
  [its transcript](agent-remote-suite.log). The shipping
  handoff test is explicitly executed separately. See [suite output](ca-remote-suites.log).
- Private-directory and lexical parent-escape regressions failed before their
  fixes. Their original output is attached. No global permission check was
  weakened: executable files, foreign ownership, world-write, symlinks and
  set-ID remain refused; group-write directories require an owned 0700 ancestor.
- Author review: [reviewer-checklist.md](reviewer-checklist.md).

An earlier fast run hit the unchanged concurrent recovery SQLite test with
`database is locked`; the isolated rerun passed in 3.10 s and subsequent full
fast gates passed the test row. No #118 baseline exception or budget change
was used. The failing output and rerun are recorded on #154.

## Distribution

Rust 1.99.0, pinned Zig 0.15.2, unchanged optimized/LTO/stripped release profile.
The unchanged production base was built separately with the same toolchain.

| Static target | Production base | Final runtime/tests | Change |
| --- | ---: | ---: | ---: |
| x86_64 musl | 19896992 bytes | 19938720 bytes | +41728 bytes |
| aarch64 musl | 17729832 bytes | 17769176 bytes | +39344 bytes |

Intermediate x86 sizes: handoff module `55645169` 19896992 (+0; not yet wired);
action declaration `de5621cf` 19897280 (+288); lifecycle `77785aa7` 19938848;
verification/hardening `5197e376` 19938720 (-128 from lifecycle).
No dependency was added or version changed. `cargo tree -d` records existing
duplicates; the dependency gate passes. The new code is removed by the remote
cargo feature, verified with `cargo check --no-default-features`.

The historical size ceilings already fail on the production base. D205 permits
this documented size-only failure; ceilings, profiles and checks are unchanged.
The fast gate exits before ARM/TS after x86 size rejection, so ARM and TS were
checked separately. [Final fast gate](gate-fast.log) and [static artifact checks](static-artifacts.log)
record the exact results. [Feature-off/dependency transcript](feature-off-dependencies.log)
records removal at build time and the existing duplicates. [TypeScript transcript](ts-fast.log) includes production
bundle checks and 34462 protocol assertions.

Reproduce the shipping proof using the server test executable built with the
remote feature, setting `INFRATERNAL_TEST_BINARY` to the stripped release binary:

```sh
systemd-run --user --scope -p CPUWeight=10000 env \
  CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/ca-handoff/target" \
  INFRATERNAL_TEST_BINARY="$HOME/.cache/codex-scratch/ca-handoff/target/x86_64-unknown-linux-musl/release/infraternal" \
  cargo test --locked -p infraternal-server --features remote --lib \
  ca_handoff::shipping_tests::shipping_restart_reload_rollback_and_cold_start \
  -- --ignored --exact --nocapture
```

The test reuses the isolated shell profile and removes its own server, shim
processes and fixture data. The deploy procedure is [deploy.md](../../docs/operations/deploy.md).
