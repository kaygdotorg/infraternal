<!-- Evidence index for immediate precise Network access retirement, D242 and #173. -->
# Mesh connection-state retirement

The initiating tuple is checked on every established/related packet by both
firewall backends. Final installation precedes exact tuple/zone/ID retirement.
Permitted same-peer flows and unrelated state remain untouched. Public intent
is durable before irreversible cleanup; a cleanup error is retried before ACK,
and recovery retains committed access throughout temporary fencing.

## Functional evidence

`functional-counts.txt` records the final 344 state/flow assertions, 20 recovery
attempts and eight failed-journal assertions. Their per-case JSON and raw state
files are in the matching directories. `recovery-red-*` retains the failing
recovery tests before repair; `review-restart-*` retains the independent
reproduction. Earlier rollback red/green evidence demonstrates that failed
persistence preserves the original state IDs. Parser fuzzing completed 100,000
executions; see `parser-fuzz.log`.

`recovery-repair-tests.log` records 37 mesh tests passing; the 42 ignored tests
require their separate real-engine harnesses. `recovery-repair-clippy.log` is the
clean touched-crate lint gate. `retained-alias-tests.log` and
`authorized-reenrollment-tests.log` each record two real-kernel passes.
`final/direct-final-*.jsonl` and `direct-final-campaign.log` record two
updated direct-path proofs on the perf VM. `reviewer-checklist.md` records author review and
qualifies the independent review.

## Measurements

See [final measurements](performance.md), `performance-summary.json` and
`final/results-final-fixed/`. All claimed performance numbers come from the
authorized VM, never from the shared build host.

`pre-journal-order/` and `pre-recovery-fence/` are historical campaigns, not final
implementation evidence. The second contains one expected reply-refusal probe
failure corrected in 7fff0c54. The final packaged executable's code hash is
recorded separately; historical artifact metadata can refer to an earlier
packaging pass and must not identify the final artifact.

## Source and gates

`commits.txt` records the atomic steps after merging dev. The contract is
`contracts/mesh-dataplane.md`. No size budget was changed. The complete final
`scripts/verify fast` output and branch head are recorded on #173.

The full fast milestone passes every Rust row except static builds. The baseline
023aee89 static x86_64 binary is 21,880,624 bytes; final runtime a707640f is
21,918,864 bytes (+38,240 bytes, +0.175%). Both exceed the unchanged
16,404,816-byte ceiling. `static-size-comparison.json` records the comparison.
This is a D243 integration blocker, not a passing gate. The script stops before
ARM static and TypeScript checks; this lane makes no claim about those stages.
