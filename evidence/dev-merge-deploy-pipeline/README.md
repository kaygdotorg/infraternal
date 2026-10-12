<!-- Records reviewed deployment integration, failing-first recovery repair and perf-VM acceptance for #188. -->
# Reviewed deployment tooling on dev ancestry

Issue [#188](https://git.kayg.org/kayg/infraternal/issues/188), D217/D244/D250/D256.
Base `efac27a598027a09abd008df952629a3cb549de5` is current `origin/dev`.
Merge `73ce87a7` includes reviewed `65a256c1` without removing any dev test
function. Exact R5 reviewer test `2dfce6e8` is cherry-picked as `ac7c1d72`;
production fix `d6333783` retains the live install pathname after an unlinked
running inode is recovered through its sealed image. Absolute service aliases
and literal suffix filenames remain intact. No signature, immutable-byte,
probe, root-only CA, anonymous launch, timeout, dependency, release profile or
size ceiling changes.

The conflict resolution keeps both dev/test SHA256 optimizations, dev's stripped
fixture cache and source/sealed inode checks, bounded PATH child cleanup, explicit
short staging CA roots with private TMPDIR fallback, and both production trust
and D244 compiler/provider gates. The staging authority remains non-default.

## Functional evidence

| Check | Result / receipt |
| --- | --- |
| Original R5 | [RED](deleted-path-red.log): 0 passed / 1 failed, actual deleted-inode label versus live pathname |
| Unchanged R5 after fix | [GREEN](recovery-green.log): 1 passed / 0 failed |
| Restart main filter | 28 passed / 0 failed / 1 explicit measurement ignore; 3 filtered integrations also pass |
| Literal suffix, linked and unlinked | [Both actual exec replays pass](literal-suffix-driver.log); [driver](literal-suffix.py) reuses existing Rust tests |
| Formatting / strict CLI all-target Clippy | [Pass](recovery-green.log); imported-test lint [pass](review-test-lint.log) |
| Merge / release / SSH suites | [Pass](merge-native-short.log): restart 27/0 before R5; server release 24/0/5 ignores; release plugin 10/0/3 ignores; SSH 108/0/8 ignores |
| Feature-enabled real CA administration | [27 passed / 0 failed / 6 shipping ignores](merge-ca.log) |
| Deployment scripts | [15 deployment, 1 packaging, 1 trust, 5 release Python and 8 Bun cases pass](merge-scripts.log) |
| Compiled release CLI / real TTY | [1 pass](channel-cli.log): stable default, both edge confirmations, disabled/absent-server refusal and action-derived skills |
| Actual stripped staging ELF in production gate | [Expected refusal, exit 1](staging-image-production-gate.txt) |

The initial [merge test run](merge-native.log) has 13 fixture setup refusals at
exactly 108 bytes in Unix socket paths. The corrected short task-owned root
passes unchanged tests. The first script run's final CLI invocation omitted
`INFRATERNAL_BIN`; the separate compiled CLI run above passes. Neither is a
product failure or a #118 waiver. Build-host test durations are functional
harness diagnostics, never performance evidence.

## Fresh locked staging proof

[Raw receipt](staging-proof.txt), run `r49dc8c39` on
`infraternal-perf-test`, kernel `6.12.69+deb13-amd64`, 4 vCPU
([machine context](perf-machine.txt)). Load before `0.08 0.17 0.25`,
after `0.35 0.23 0.27`.

| Check | Result |
| --- | --- |
| Signed alternating handoffs | 12 accepted, CA stays unlocked after one real passkey unlock |
| Listener-gap bracket p50 / p99 | 18.159 / 26.088 ms, nearest rank, n=12 |
| Worst actual probe spacing | 4.738 ms; nominal 1 ms samples |
| Full transaction p50 / p99 | 635.844 / 681.098 ms, including backup and separate payload authentication |
| Scale / continuity | 50 users, 10000 retained nodes; all 128 shim PIDs and all 128 fresh input/output resumes survive |
| Signed unusable C | Refused before shutdown; actual deploy transaction verifies warm B rollback and unlocked CA |
| Backup | Integrity and 10000-node / 50-user counts pass; retained previous-image signature verifies |
| Lock scope | Upload/extraction outside lock; native acceptance under `flock -w 3600`; released before directory cleanup |
| Teardown | Own unit/processes/data/CA/runtime removed; directory absence confirmed |

These listener values are conservative availability brackets, not exact
blackout or end-to-end terminal reconnect measurements. No causal speedup is
claimed against earlier runs with different load and sampling gaps. A/B execute
one staging program with distinct signed identities and hashes; the signed ARM
placeholder is never executed or a production artifact. Fresh private signing
material is deleted before transfer. No production deployment, signer/provider
access, service installation, dev/main update, tag or issue closure occurred.

Run from this worktree with the task's HOME-cache scratch and unique port:
`TRACER_TEST_PORT=4391 scripts/release/staging-proof --scratch
$HOME/.cache/codex-scratch/dev-merge-deploy-pipeline --evidence
evidence/dev-merge-deploy-pipeline/staging-proof.txt`.

[Author integration checklist](reviewer-checklist.md) completed. The final
exact-head `scripts/verify fast` transcript and head SHA are posted verbatim on
#188 after this evidence commit. D243's existing maxima remain 16,404,816 bytes
for x86 and 13,817,816 bytes for ARM; the known size refusal is not waived and
cannot be used as a production publish/deploy gate. No TypeScript/UI production
source changed.
