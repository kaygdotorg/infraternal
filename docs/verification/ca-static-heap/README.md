<!-- Records the static provider diagnosis, D244 repair, root proof and verification boundaries for #154. -->
# Static key-memory refusal

> Raw run receipts cited here were removed under D262. The diagnosis, measurements and
> reproduction method remain; new outputs belong in job scratch and should be attached to #154
> with the `issue-attach` helper.

Investigation base: `audit-ca-update` at `b0cf61ef`. Production batch
`8cff05cd` pins the identical provider: openssl-src 300.6.1+3.6.3 and
openssl-sys 0.9.117. All #154 comments were read; no linked parent exists.

The cause is compile-time removal of the secure allocator. openssl-src
`src/lib.rs:631–634` adds `-DOPENSSL_NO_SECURE_MEMORY` for every musl target.
The generated x86 Configure command contains that define. In
`crypto/mem_sec.c:109–127`, initialization returns `0` unconditionally,
without attempting page locking or dump exclusion. The historical
[upstream issue](https://github.com/openssl/openssl/issues/7207) concerned a
missing Linux header. Pinned Zig 0.15.2 compiles this implementation when
the define is absent.

## Root reproduction

The recorded systemd rows came from the explicitly authorized benchmark VM, Linux
6.12.69+deb13-amd64, as root under `/var/lock/perf-bench.lock`. Only synthetic
allocations were made. No keys, dump contents or addresses were printed.

| Static provider diagnostic | LimitMEMLOCK | Return | VmLck | Outcome |
| --- | --- | --- | --- | --- |
| Baseline | 8 MiB | 0 | 0 KiB | refused |
| Baseline | unlimited | 0 | 0 KiB | refused |
| Baseline | unit default (8 MiB) | 0 | 0 KiB | refused |
| Candidate | 8 MiB | 1 | 1,024 KiB | protected |
| Candidate | unlimited | 1 | 1,024 KiB | protected |
| Candidate | unit default (8 MiB) | 1 | 1,024 KiB | protected |

The candidate replaces only the disabled mem_sec.c archive implementation
with an object compiled without the define. It is an unshipped measurement,
not a production build-policy change. All 10,000 synthetic 32-byte
allocations were resident, reported as secure, and occupied mappings with
both `lo` and `dd` flags. Secure usage was 320,000 bytes and returned to zero
after freeing. The locked heap is 1 MiB per server, independent of
host/session count. Increasing memlock or changing sandbox properties
cannot enable code removed by compilation.

The stripped static x86 provider diagnostic is 3,873,384 bytes baseline
versus 3,881,736 candidate: **+8,352 bytes**. This is not the final server
size delta. The full-server baseline and aarch64 provider builds were
interrupted at the owner boundary. Both musl targets receive the same
unconditional disable flag; no architecture-specific syscall failure is
needed to explain the current refusal. No aarch64 runtime result is claimed.
Single initialization timings are diagnostic observations, not performance
benchmarks. Machine load is in the transcript; no load generators ran.

## Original owner boundary (resolved by D244)

The brief requires: “If the repair needs a different OpenSSL build option
or a new dependency, that is a foundational choice: stop and write the
question on #154 with the measured options.” The
The question and options were posted on #154. Recommendation: remove the exact musl disable define
through the pinned compiler wrapper; alternative: maintain an explicit
openssl-src patch. Neither requires a new engine.

At the diagnostic handoff, no production Rust, wrapper, manifest, lockfile
or decision had changed. Root fail-closed remained intact. The repair and
static executable regression were pending the owner build-policy choice.
The D244 implementation below resolves that boundary. After that choice, exercise the
real static release executable under 8 MiB and verify return `1`, resident
locked pages, dump exclusion and actual provider key allocation; measure
both final binary sizes and startup cost. This provider probe alone is not
a whole-server release proof.

## Reproduction and verification

Build the pinned provider with the repository toolchain and Cargo.lock:

```sh
export CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/ca-static-heap/target"
scripts/auth-toolchain
nix shell nixpkgs#gnumake nixpkgs#perl -c cargo build --locked --release \
  --package openssl-sys --target x86_64-unknown-linux-musl
python3 docs/verification/ca-static-heap/build_probe.py "$CARGO_TARGET_DIR" x86_64
```

The C probes compiled with `-Wall -Wextra -Werror`. The final root runner
asserts baseline exit `1` and candidate exit `0` for all three limits.
Shell syntax, Python compilation, Rust formatting and `git diff --check`
passed. No Rust or TypeScript module was touched.

The full fast gate was invoked locally in a CPUWeight=10000 scope with
TRACER_TEST_PORT=5814, one Rust test thread and job-owned scratch paths.
Network self-test and formatting completed; Clippy was still compiling at
the owner boundary. The run was interrupted (exit 130), along with the
queued full-server and aarch64 builds. No final summary or full-test/static
pass is claimed. The raw transcript was removed under D262.

Author checklist: compile condition traced; no credential inspection;
authorized VM and lock used; real kernel flags checked at 10,000 allocations;
root refusal retained; no engine chosen; diagnostic size distinguished from
server size; GNU results not substituted for musl proof; incomplete gate
and owner boundary recorded. Independent review remains required after repair.


## D244 production repair (2026-10-12)

The owner selected option (a) in `origin/dev` decision 244 at `63dabc80`.
[The pinned wrapper](../../../.cargo/musl-cc.sh) removes exactly
`-DOPENSSL_NO_SECURE_MEMORY`; every other argument and the target guard
remain intact. OpenSSL 3.6.3, openssl-src 300.6.1+3.6.3, openssl-sys 0.9.117,
sources, dependency versions and release profiles are unchanged.
The upstream Configure command still contains its argument; filtering happens
at the final compiler invocation. A Configure log alone cannot validate this repair.

The hidden `__key-memory-check` command creates/imports no keys and succeeds
only when the existing audited initializer returns **1**, for root and
ordinary users alike. It supports the existing human/JSON presentation and
is absent from public help and remote-disabled builds. The ordinary server's
root refusal/non-root development policy is unchanged.

[The static build gate](../../../scripts/verify.d/rust.sh) executes the actual
release binary under `prlimit --memlock=8388608` and fails on any other result.
It retains every size failure while continuing through both target builds
and heap checks. Kernel protection is checked natively. This Linux x86_64
host cannot execute the ARM image natively, so the ARM runtime check is
explicitly reported as untested. No ARM runtime result is claimed.

### Shipping image sizes

Both original-production reference images omit the diagnostic. These are
full repair deltas, not the earlier standalone C-probe measurements.
The recorded hash, file-identification and interpreter checks are summarized below; their raw receipt was removed under D262:

| Target | Before | After | Delta | Unchanged ceiling |
| --- | ---: | ---: | ---: | ---: |
| x86_64 musl | 20,090,384 B | 20,098,960 B | +8,576 B | 16,404,816 B |
| aarch64 musl | 17,906,336 B | 17,914,528 B | +8,192 B | 13,817,816 B |

Both images are stripped and static, with PT_INTERP absent. The old ceilings
already fail on both reference images and remain unchanged (D243).
The measured additional bytes implement the owner's D244 protection choice.

### Root systemd proof and startup measurements

The actual production CLI startup receipt was removed under D262; its result is summarized below:
`infraternal-perf-test`, Linux 6.12.69+deb13-amd64, 4 CPUs, root, shared perf
lock held, systemd CPUWeight=10000 and LimitMEMLOCK=8388608. Load before and
after: 0.01/0.06/0.06. No load generators or builds ran on the VM.

- Original static server: refused, exit 1, even under 8 MiB.
- Repaired static server: all 21 starts reach `/healthz` 200; VmLck **1,024 KiB**;
  actual mappings with both `lo` and `dd` flags total **1,024 KiB**.
- Root with LimitMEMLOCK=0 and CAP_IPC_LOCK removed: still refused, exit 1.
- 31 alternating, otherwise identical diagnostic pairs: process p50
  2.684 ms before / 2.563 ms after; maxima 4.653 / 3.609 ms. The observed
  -0.121 ms median difference is not a causal improvement claim.
- Server refusal before: p50 3.815 ms / max 6.059 ms. Successful server
  readiness after: p50 **57.143 ms** / max **153.004 ms**. The original server
  cannot provide a successful-start baseline; these two timings are not
  comparable as a healthy startup regression.

No addresses, key material or dump contents are printed. Server output during
successful startup is discarded so its setup capability cannot enter evidence.

### Real static CA and scale proof

The root static-release CA receipt was removed under D262.
uses the existing release/musl test executable with the remote feature, under
root/systemd 8 MiB and the same shared lock. All **3 selected tests pass**:
locked imported signer, real passkey HTTP authority unlock, and 10,000 live
keys. The authority test exercises its real router/encrypted copies; it is
separate from the standalone shipping CLI startup proof, and is not a live
production/browser deployment claim.

The unlocked source has VmLck 1,024 KiB, 832 secure bytes, and asserts the
additional imported seed's +32 B allocation and release. At **10,000 keys**:
320,512 secure bytes (32 B/key plus 512 B provider state), 1 MiB locked per
server, 69.4% heap headroom; dropping keys leaves 512 B of provider state.
The heap is per server, independent of host/session count. RSS before/live
keys is 6,372/12,800 KiB without initialization versus 8,060/12,764 KiB with
initialization; single-process endpoints, not a whole-server memory improvement.
Scale load: 0.05/0.04/0.01 before; 0.13/0.05/0.01 after.

### Reproduction, gates and author review

Keep build targets/worktrees in a job-owned CARGO_TARGET_DIR and use a short
INFRATERNAL_TEST_STATE_ROOT. For the full native test suite, preserve the small
fixtures' normal short `/tmp` path: the gone-session fixture appends a UUID and
session socket name. A long job TMPDIR produced a 157-byte pathname versus
105 bytes with `/tmp`, exceeding Linux's 108-byte bound including NUL. The
unchanged exact test then passed in 0.06 s with the short fixture path; no
assertion/deadline change or #118 waiver. The root CA harness separately uses
its job-owned TMPDIR for the selected CA tests. No build targets or temporary
worktrees are placed in `/tmp`.

After changing compiler policy, clean only the affected release provider
outputs to avoid reusing a disabled archive:

```sh
cargo clean --release -p openssl-sys --target x86_64-unknown-linux-musl
cargo clean --release -p openssl-sys --target aarch64-unknown-linux-musl
scripts/verify fast
```

Build drivers are supplied through the documented Nix gnumake/perl invocation.
Preserve RUSTC_WRAPPER for the compiler cache. The native runtime gate requires
prlimit; the cross-target build still requires the pinned D213 toolchain.
The reproducible root harness is
[run-d244-root.sh](run-d244-root.sh) plus
[run_d244_root.py](run_d244_root.py), run in
`/root/infraternal-bench/ca-heap/` only while holding the shared perf lock.
Its explicit split modes preserve startup and CA receipts separately.

Targeted fmt, touched-package all-target Clippy, CLI limit/JSON/help test,
real passkey fixture test, feature-off CLI check, both release builds, exact
wrapper-policy tests, shell/Python syntax and diff checks pass. Initial new-test
assert-is-empty lint output is retained alongside the corrected passing run.
The remote-only release test build has two existing dead-code warnings for
mesh-only fields; the touched-package default-feature Clippy gates pass.

The final branch-head `scripts/verify fast` output and head SHA are recorded
verbatim on [#154](https://git.kayg.org/kayg/infraternal/issues/154). Both old
size ceilings remain exceeded; no green full size-gate claim is made.

Author checklist: owner choice followed exactly; no engine/version/source or
other provider option changed; root zero-limit refusal retained; real shipping
static binary rather than GNU substituted; real lo/dd and imported allocation
checked; 10,000-key scaling recorded; ARM runtime explicitly untested; no key
material/credentials inspected or emitted; no load generators, push outside
the authorized branch, deployment, host-key changes, or issue closure. Source,
tests, gate and proof are separate atomic commits. Independent review remains
an orchestrator step. Only this job's scratch/uploaded artifacts are removed.
