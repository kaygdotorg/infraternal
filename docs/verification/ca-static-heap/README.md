<!-- Records the static provider diagnosis and owner build-option boundary for #154. -->
# Static key-memory refusal

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

[Raw systemd output](../../../evidence/ca-static-heap/root-systemd.txt)
comes from the explicitly authorized infraternal-perf-test VM, Linux
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

## Owner boundary

The brief requires: “If the repair needs a different OpenSSL build option
or a new dependency, that is a foundational choice: stop and write the
question on #154 with the measured options.” The
[question and options](../../../evidence/ca-static-heap/foundation-question.txt)
were posted on #154. Recommendation: remove the exact musl disable define
through the pinned compiler wrapper; alternative: maintain an explicit
openssl-src patch. Neither requires a new engine.

No production Rust, wrapper, manifest, lockfile or decision was changed.
Root fail-closed remains intact. Repair and the static executable regression
are pending the owner build-policy choice. After that choice, exercise the
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
python3 evidence/ca-static-heap/build_probe.py "$CARGO_TARGET_DIR" x86_64
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
pass is claimed. [Captured output](../../../evidence/ca-static-heap/verify-fast.txt).

Author checklist: compile condition traced; no credential inspection;
authorized VM and lock used; real kernel flags checked at 10,000 allocations;
root refusal retained; no engine chosen; diagnostic size distinguished from
server size; GNU results not substituted for musl proof; incomplete gate
and owner boundary recorded. Independent review remains required after repair.
