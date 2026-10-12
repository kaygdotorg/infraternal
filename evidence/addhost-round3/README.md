<!-- Repair decisions, executable regressions and retained evidence for host provisioning round 3, #169. -->
# Host provisioning round 3

Branch `addhost-fixes2`, starting at `9cdab5c7`. Reviewed acceptance source
`origin/review-addhost-fixes2`=`ff0285f6`; issue history was read before each
continuation and has no linked parent. Implementation is confined to this
worktree. No owner live fixture, unrelated lab machine, deployment or default
branch update is used.

| Finding | Repair | Before | After |
| --- | --- | --- | --- |
| V1: listed name plus typed port loses inventory address | `bf0bfd08`, existing typed-chip address field | 3 pass / 1 fail | add-host source 50 pass / 0 fail |
| V2: empty owned receipt defeats rollback | `81993854`, exact acquisition recovery | 0 pass / 1 fail | real-shell install 40 pass / 0 fail |
| V3: payload Join71 gets directory advice | `77ea8505`, preserve Join boundary | 0 pass / 1 fail | install 41 and diagnostics 8 pass / 0 fail |
| V4: cancellation loses retirement behind a writer | `6afe96b6`, `f11c6be7`, `695d00e4`, `47f28289`, `a58529b1`, `a48eb11e`, `3a6d5580`, `2481499a` | unchanged review 0 pass / 1 fail (active host records 2, expected 1) | provisioning 10 pass / 0 fail / 2 opt-in ignored; VM writer regressions 2 pass / 0 fail |

The original review regressions retain their assertions. V4's imported file is
byte-for-byte equal to test commit `0e9717ae` (SHA256
`383bf8cd3238ea4ce3ab029d11f6806bdab41c4250e9e006e815e765fbf7cf84`). V1/V2/V3
acceptance comes from `2bfa2da3`, `5632b02b`, `cabed7b6`; their red and green
transcripts are retained. The initial V4 default-feature invocation selected
zero tests and is not accepted as evidence; `v4-red-remote.log` is the real red.

V4 uses a retirement intent in the invitation transaction, because SQLite
cannot update the host record synchronously while another writer owns its
slot. A synchronous transport fence prevents continued admission while an
owned writer waits. Tombstone and intent consumption commit together. Timeout
of the caller acknowledgement detaches the writer, and only transient SQLite
BUSY/LOCKED or pool-acquisition failures retry. Other storage failures retain
fence and intent; startup retires unfinished intents before listeners admit
connections. Successful proven completion acknowledges intent removal before
Done. Prior completed host records without an intent remain protected.

The additional real-file two-connection regression forces SQLite BUSY after its
configured timeout; the independent one-connection review regression remains
unchanged. Exact-owner retirement, missing-intent refusal, completion and
idempotent startup recovery pass. Migration 23 is additive; no dependency,
foundational engine or wire frame changes. The lifecycle clarification was
proposed on #169 before implementation and is now in `contracts/ssh-bootstrap.md`.

Browser production replay: **27 pass, 0 fail**, unique `TRACER_TEST_PORT=4331`,
`browser-27-service2.log`, exit 0. Earlier proxy disappearance, IPv6/IPv4 mismatch
and interrupted scope are retained, with no product assertion waiver. Existing
visuals are unchanged; the production screenshot `captures/failure-details.png`
is attached for independent assessment. No author visual-quality verdict or
physical-iPhone claim.

Functional daemon measurement separation `47ca472d`: real refusal-sentinel
regression fails before and passes after, with all 24 stop/restart assertions
retained. Default performance thresholds are unchanged. Portable opt-in observer
`a3f9e7c9` forwards the synchronous retirement hook and records actual VM identity.
[Performance evidence](performance.md) has the 21 passing pinned-VM diagnostics,
per-step ranges, payload reuse counts and 1600-host admission bounds. Prior
shared-build-host timings are superseded as performance evidence.

[Author checklist](reviewer-checklist.md) covers trust, exact ownership, uid,
root consent, cancellation, startup, secrets, bounds and component reuse.

Gate environment corrections are retained separately: the milestone gone-session
fixture exceeded SUN_LEN. `b0a0bda9` removes the long fixture prefix, but the full
job TMPDIR still produced 119-byte paths; the job-owned compact HOME-cache alias
reduces that path to 107 bytes and the exact case passes. The RTT delegation
wrapper initially forwarded other scripts to system Python 3.13 rather than
workspace Python 3.14, causing Path.exists PermissionError in session-bounds;
preserving the original interpreter fixes the exact replay. No source assertion,
timeout, budget or #118 baseline exemption was changed or applied. RTT self-test
runs unchanged on the locked perf VM through the retained job wrapper.

Final `scripts/verify fast` on the repaired code: exit 1 solely at the inherited
static-size row; native 679 pass / 0 fail / 68 ignored. No load/baseline exemption.
Full raw output: `verify-final.log`; RTT timing is from the perf VM. Compiler,
source tests (161/0), production build/transfer and protocol tests (36/0) pass
separately in `final-ts.log`, exit 0, because the dispatcher returns at size.

Both architecture builds succeed, stripped/static/no PT_INTERP. [Static evidence](static-size.md)
retains unchanged caps and exact byte counts. x86 growth is 24,096 bytes against
the reviewed original head, which already exceeded the cap; no original ARM
delta is claimed. D205 allows reported feature growth; size is not called PASS.
CLI stubs pass separately. No profile, dependency, feature or budget change.

Verbatim final fast summary:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```

The source fixes and measurement/docs are atomic commits; the final evidence
commit changes no compiled source. Head SHA, branch push and the verbatim gate
summary are recorded on [#169](https://git.kayg.org/kayg/infraternal/issues/169).
The issue remains open. No deployment or default branch update.

