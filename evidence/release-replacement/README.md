<!-- Indexes exact-byte replacement, CA recovery, performance and gate evidence for #157/#154 [217,224,226]. -->
# Safe binary replacement — round 4

Branch `release-pipeline`, integrated base `22aeb7b2` (dev plus round 3).
The original three audit tests came unchanged from
`origin/review-audit-ca-update-wip`; each failed before its correction. P3 came
from `5eac0558` and also failed before the restrictive-umask correction.

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
  replacement and forced late candidate-exec refusal both preserve the PID,
  restore the unlocked CA and serve. Final oracle: 17.32 seconds. Only public
  issuer/signature/trust fixture material reaches files; private keys remain in
  memory. Network is disabled; the Nix loader is mounted read-only.
- [recovery-harness-after.txt](recovery-harness-after.txt): same real exec cases
  under the unoptimized native profile, 24.04 seconds; rootless behavior remains
  explicitly cold.
- [probe-control-before.txt](probe-control-before.txt) and
  [probe-image-gate.txt](probe-image-gate.txt): inherited control fd3 failed before
  correction; both the four-seal mutation and actual probe/ELF tests pass (0.51s).
- [anonymous-agent-before-short.txt](anonymous-agent-before-short.txt) and
  [anonymous-agent-after.txt](anonymous-agent-after.txt): the integrated baseline
  refuses a real PTY after anonymous exec; the corrected shipping image accepts
  terminal input/output with control-fd isolation.
- [anonymous-prompt.txt](anonymous-prompt.txt): optimized sealed anonymous-image
  producer copies its exact 1,260,800-byte running fixture into private staging,
  then authenticates one real child reply. Preparation: 16.355ms under weighted
  scope while the ARM build was still active. This is fixture timing, not a
  shipping-image timing or a claim of linear scaling.
- [credential-gate-final.txt](credential-gate-final.txt): four credential scope,
  permission, cleanup and unrelated-peer tests pass (221.24s unoptimized).
  [askpass-gate-final.txt](askpass-gate-final.txt): 13 unit tests and preceding
  integration slices pass; its unrelated config fixture hit a load timeout.
  [config-isolation-retry.txt](config-isolation-retry.txt): that row passes fresh
  under weighted scope (0.06s). [bootstrap-gate.txt](bootstrap-gate.txt): 15 server
  bootstrap tests pass (61.14s).

The SSH bootstrap's existing global semaphore permits eight hosts across all
batches, not eight per request. Each prompt copy has the size of the running
image; its transient disk/page-cache upper bound is eight times that size.
Copies are removed after authentication or scope drop. This is a bound, not an
isolated RSS measurement. Missing passphrases incur no image copy or hash.

## Parser and failure receipts

[manifest-fuzz-execution.txt](manifest-fuzz-execution.txt): ASan target completed
3,657,436 runs in 61 seconds with no finding. It includes canonical identity
framing and the existing SSHSIG/checksum parser. Structured seeds contain only
public manifest data, never valid private CA frames.

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

## Measurement and gate qualification

Measurements run locally on `infraternal-dev`, observed 12 CPUs, under
`systemd-run --user --scope -p CPUWeight=10000`; each final performance receipt
records host load. The listener harness uses 25 real same-PID self replacements,
50 users, 10,000 retained hosts and zero live PTYs, sampling TCP every configured
1ms. Retained rows are not live connections. Shared-host scheduling and sampling
uncertainty qualify comparisons; these measurements do not certify terminal
latency, live-session scale or production hardware budgets.

The independent x86 baseline was built from `22aeb7b2`: 21,709,776 bytes.
The ARM comparison uses the integrated baseline's issue #157 receipt,
19,224,296 bytes; it was not independently rebuilt here. The ARM head is 19,246,960 bytes (+22,664), with no PT_INTERP. The historical ceilings
remain 16,404,816 and 13,817,816 bytes, respectively. No baseline was raised.

The full fast command uses the integrated baseline's recorded native RSS
profile [gate-profile.toml](../release-integrate/gate-profile.toml), optimizing
only the CLI, infraternal agent and plugin API to level 1. Dependencies and both
production release profiles remain unchanged. Targeted default-profile clippy
also passes. This is a qualified native RSS result, not an unoptimized-default
RSS claim. The first head attempt stopped at the latency self-check under host
load; the weighted retry is the final Rust gate receipt. The dispatcher stops
at Rust failure, so TypeScript is verified separately:
[ts-supplement-retry.txt](ts-supplement-retry.txt) passes compiler, production
build/transfer budget, 158 tracer/unit tests and 36 protocol tests. Its first
attempt had an existing 1,000-node timing failure and is retained separately.

macOS has source inspection only: private verified copies retain same-owner
mutation risk and may remain after successful exec. The both-exec-refusal
loaded-code fallback was inspected for stdin lifetime; the actual recovery
oracle refuses only the candidate exec. No equivalent Mac runtime guarantee or
both-exec runtime proof is claimed.
