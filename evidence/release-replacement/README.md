<!-- Indexes exact-byte replacement, CA recovery, performance and gate evidence for #157/#154 [217,224,226]. -->
# Safe binary replacement — round 4

Branch `release-pipeline`, integrated base `22aeb7b2` (dev plus round 3).
The original three audit tests came unchanged from
`origin/review-audit-ca-update-wip`; each failed before its correction. P3 came
from `5eac0558` and also failed before the restrictive-umask correction.

Current latency and verification timings below use the perf VM receipts. The
older `listener-before-private.txt` measurement remains as historical shared
build-host evidence and is not used for the before/after comparison.

## Behavior and provenance

- `cd90df2f`: original UP-01/02/03 audit oracles and failing-before receipts.
- `0b5a1000`: exact private staging permissions under owner-restrictive umask.
- `53de3b5d`: canonical identity-bearing MANIFEST signature verification,
  reusing existing OpenSSL trust and digest machinery. The hardened signer's
  additional MANIFEST/MANIFEST.sig objects are required; old checksums alone
  cannot admit an explicit replacement. Existing checksum consumers remain
  compatible with the signer's separately retained SHA256SUMS objects.
- `6ba9d5c8`, `2aad952d`: bounded immutable snapshots and real signature/hash
  admission over execution bytes; exact kernel-byte exception only for self reload.
- `a8eb2443`, `552fbaa2`: audited child policy, admission probe before shutdown,
  independent retained current image and CA receiver for late exec refusal.
- `8c7572fb`, `49ec3b70`: real embedded infraternal agent/shim launch from the
  kernel image after anonymous exec, with direct child isolation.
- `95b9c971`, `1170380c`: scoped SSH prompt copy authenticated by peer parent,
  UID, device/inode and expected kernel-source digest; correct sibling discovery.
- `1d78a002`: real inherited-fd3 probe regression, explicit isolation and
  descriptor reservation above fd3.
- `6ec9e1b5`: separately bounded debug fixture/admission preparation; the actual
  recovery observation remains 30 seconds. Production deadlines are unchanged.
- `b63b05f5`: operations guidance and explicit macOS qualification.

Each step was pushed separately. Commit bodies record choices and rejected
alternatives. Issue #157 records start, findings and step receipts; #154 records
CA-specific progress. [review.md](review.md) records the author checklist and
independent read-only reviews.

## Real execution evidence

- [root-ca-final-sudo.txt](root-ca-final-sudo.txt): a root container with real
  fexecve, sealed images, protected CA transport and TCP listener. Successful
  replacement and forced late candidate-exec refusal both report
  `same_pid=true ca_unlocked=true serving=true`; the test passes 1/1. Only public
  issuer/signature/trust fixture material reaches files; private keys remain in
  memory. Network is disabled; the Nix loader is mounted read-only.
- [recovery-harness-after.txt](recovery-harness-after.txt): same real exec cases
  pass under the unoptimized native profile; rootless behavior remains
  explicitly cold.
- [probe-control-before.txt](probe-control-before.txt) and
  [probe-image-gate.txt](probe-image-gate.txt): inherited control fd3 failed before
  correction; both the four-seal mutation and actual probe/ELF tests pass.
- [anonymous-agent-before-short.txt](anonymous-agent-before-short.txt) and
  [anonymous-agent-after.txt](anonymous-agent-after.txt): the integrated baseline
  refuses a real PTY after anonymous exec; the corrected shipping image accepts
  terminal input/output with control-fd isolation.
- [anonymous-prompt.txt](anonymous-prompt.txt): optimized sealed anonymous-image
  producer copies its exact 1,260,800-byte running fixture into private staging,
  then authenticates one real child reply. This is fixture evidence, not a
  shipping-image measurement or a claim of linear scaling.
- [credential-gate-final.txt](credential-gate-final.txt): four credential scope,
  permission, cleanup and unrelated-peer tests pass. [askpass-gate-final.txt](askpass-gate-final.txt):
  13 unit tests and preceding integration slices pass; its unrelated config
  fixture hit a load timeout. [config-isolation-retry.txt](config-isolation-retry.txt):
  that row passes fresh. [bootstrap-gate.txt](bootstrap-gate.txt): 15 server
  bootstrap tests pass.

The SSH bootstrap's existing global semaphore permits eight hosts across all
batches, not eight per request. Each prompt copy has the size of the running
image; its transient disk/page-cache upper bound is eight times that size.
Copies are removed after authentication or scope drop. This is a bound, not an
isolated RSS measurement. Missing passphrases incur no image copy or hash.

## Parser and failure receipts

[manifest-fuzz-execution.txt](manifest-fuzz-execution.txt): ASan target completed
3,657,436 runs with no finding. It includes canonical identity
framing and the existing SSHSIG/checksum parser. Structured seeds contain only
public manifest data, never valid private CA frames. Its shared-host wall time is
retained in the raw receipt and is not used as performance evidence.

[manifest-fuzz.txt](manifest-fuzz.txt) retains the first sanitizer/LTO link
failure. [manifest-fuzz-retry.txt](manifest-fuzz-retry.txt) records successful
instrumented compilation with release LTO disabled and compiler-cache bypassed;
the wrapper then blocked on tool/package locks. Its job-owned scope was stopped
and the already-built ASan target ran directly in the weighted execution receipt.
This does not change production profiles.

Original failing oracles, umask red/green, closed-stdin corrections, first
unsupported staging/socket paths and earlier gate attempts remain here. They
are failures or diagnostic receipts, never counted as passes. Byte dumps remain
in files and are not copied into issue prose.

## Round 4 acceptance and perf-VM measurements

UP-01, UP-02 and UP-03 each failed as a single-test oracle against the
`b0cf61ef` behavior. UP-01 admitted all 4/4 unsigned or tampered candidates;
UP-02 exposed changed bytes through the retained descriptor; UP-03 stopped the
existing listener after the admitted image refused execution. In
[recovery-gate-final.txt](recovery-gate-final.txt), all three named tests pass
in the 25 passed / 0 failed restart suite. The final UP-01 metric is
`unverified_replacements_accepted=0 candidates=4 executed=0`.

The real root-container replacement oracle in
[root-ca-final-sudo.txt](root-ca-final-sudo.txt) covers both a successful
replacement and a late candidate-exec refusal. Both preserve the same PID,
serve the listener and restore the unlocked CA (`same_pid=true
ca_unlocked=true serving=true`).

The timings below were collected on `infraternal-perf-test` (Debian 13,
x86_64, 4 vCPU) under `flock /var/lock/perf-bench.lock`, in
`/root/infraternal-bench/release-r4/`. The listener runs started and ended at
load average 0.020 / 0.043 / 0.006. It performs 25 same-PID self replacements
per binary, with 50 fixture users, 10,000 retained host rows, no live PTYs and
1 ms TCP probes. These are retained rows, not live connections.

| Binary | Listener gap p50 / max | Full self-replacement p50 / max |
| --- | ---: | ---: |
| Integrated base `22aeb7b2`, 21,709,776 B | 9.105 / 17.466 ms | 10.281 / 17.911 ms |
| Round 4 head, 21,736,368 B | 10.693 / 14.593 ms | 50.204 / 83.468 ms |

Both runs preserved the same PID. The listener gap p50 increased by 1.588 ms;
the full self-replacement p50 increased by 39.922 ms. This harness requests a
self reload of the exact running image; it measures listener availability and
probe/exec overhead, not admission of a different signed candidate. The
1 ms sampling interval and 25 samples bound the comparison's precision.
Receipt: [listener-perf-vm.txt](listener-perf-vm.txt).

The full signed verifier hook checked a 20 MiB (20,971,520-byte) synthetic
payload 50 times on the same perf VM. Its p50 was 79.029 ms; the release-profile
test passed 1/1. Load average was 0.00 / 0.03 / 0.00 before and 0.08 / 0.04 /
0.01 after. The test harness was built from the branch's release verifier tests
with the pinned Rust 1.99.0 profile, copied to the VM, and executed there. The
VM has no Rust/C toolchain, so the harness used its copied glibc loader and
runtime libraries inside the job directory. Receipt:
[verify-20m-perf-vm.txt](verify-20m-perf-vm.txt).

Static artifact sizes from the integrated base and round 4 head:

| Target | Base | Round 4 head | Delta | Existing maximum |
| --- | ---: | ---: | ---: | ---: |
| x86_64 musl | 21,709,776 B | 21,736,368 B | +26,592 B | 16,404,816 B |
| aarch64 musl | 19,224,296 B | 19,246,960 B | +22,664 B | 13,817,816 B |

Both head artifacts are stripped static images with no `PT_INTERP`. The
unchanged historical size ceilings are exceeded by 5,331,552 B and 5,429,144 B;
no baseline was raised. ARM's base value is the integrated branch receipt and
was not independently rebuilt in this lane. See
[static-final-both.txt](static-final-both.txt).

## Gate qualification

The full fast command uses the integrated baseline's recorded native RSS
profile [gate-profile.toml](../release-integrate/gate-profile.toml), optimizing
only the CLI, infraternal agent and plugin API to level 1. Dependencies and both
production release profiles remain unchanged. Targeted default-profile clippy
also passes. This is a qualified native RSS result, not an unoptimized-default
RSS claim. The first head attempt stopped at the latency self-check under host
load; its shared-host timing is not used as performance evidence. The weighted
retry is the final Rust gate receipt. The dispatcher stops at Rust failure, so
TypeScript is verified separately:
[ts-supplement-retry.txt](ts-supplement-retry.txt) passes compiler, production
build/transfer budget, 158 tracer/unit tests and 36 protocol tests. Its first
attempt had an existing 1,000-node timing failure and is retained separately.

macOS has source inspection only: private verified copies retain same-owner
mutation risk and may remain after successful exec. The both-exec-refusal
loaded-code fallback was inspected for stdin lifetime; the actual recovery
oracle refuses only the candidate exec. No equivalent Mac runtime guarantee or
both-exec runtime proof is claimed.
