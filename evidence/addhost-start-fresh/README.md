<!-- Host provisioning start-fresh implementation, acceptance evidence and gate disposition for #169. -->
# Host provisioning: start fresh

Assigned base: `6be5514d7f120380bb57b20e0b92ad7329dee0c4`,
`origin/addhost-fixes2`. Source finishes at `a83c5d91`; no deployment or changes
to the owner's live fixtures. Exact copy and additive contract were proposed
on #169 before implementation. UI implementation belongs to the later pass.

The existing SSH check returns typed `stale_previous_attempt` before invitation
or upload. An authenticated, single-use, exact-target `start-fresh` confirmation
rechecks ownership, complete supported inventory, inode binding and liveness,
then removes only proven fresh artifacts through the existing rollback and
continues the same attempt. Foreign files, changed observations, live sockets
(including bound-before-listen), processes or lock holders refuse before removal.
Older inode-unbound journals and advanced unknown staging layouts refuse with
an explicit reason. Directory flock and a bounded lease cover command gaps.
The descriptor supplies the exact “Start fresh” label for all adapters.

## Acceptance

- SSH full targeted suite: 103 passed, 0 failed, 8 opt-in ignored; remote server
  host provisioning: 41 passed, 0 failed, 3 opt-in ignored. The tests prove one
  attempt/invitation, challenge/owner/target admission, replay refusal, component
  cancellation with zero work and intact leftovers, and content-free logs.
- Final ownership shell: 15 passed, 0 failed, actual files and Unix sockets,
  real executable and lock holders. The issue records the original stale failure; regression logs retain
  foreign root/lock, changed acquisition, missing owner marker and bound-socket
  failures before their repairs. Private roots and every receipt are validated
  before removal. No owner fixture is read, modified, moved or deleted.
- fmt and strict touched-crate Clippy pass. Decoder fuzz target is updated and
  compiled in the normal remote+SSH feature union. Instrumented fuzzing is not
  claimed. A fuzz-only remote-without-SSH check exposed inherited unused-code
  errors; no source exemption was applied.
- TypeScript full compiler/source/build/transfer gate: 161 source tests and 36
  protocol tests (34,462 assertions) pass; no UI changes or visual claim.
- Booked perf VM, shared lock: 101 paired clean checks, median addition 4.438 ms,
  no extra SSH round trip; stale checks median 74.745 ms. Temporary lease
  1,908 KiB × eight = 15,264 KiB, 180-second ceiling, no periodic work. Real
  NetBird SSH command closure preserves the lease; exact retirement passes.
  Raw data, input hashes and limitations are in [performance.md](performance.md).

## Gate record and disposition

Milestone `scripts/verify fast` exposed a 108-byte fixture socket under the
three-character `asf` scratch root. The exact compiled test passes with the
newly owned two-character `af` root, yielding 107 bytes. No source, deadline
or assertion changes and no #118 exemption. `gone-compact-replay.log`.

Milestone static x86 output: stripped/static/no PT_INTERP, 20,175,632 bytes,
versus 16,404,816-byte cap. Supplied base's retained measurement is 20,132,112
bytes (`evidence/addhost-round3/static-size.md`); observed increment 43,520 bytes.
D243 remains in force; no cap, release profile or dependency is changed.
The dispatcher stops before ARM and TypeScript on that failure; TypeScript was
run independently above. Final source/head size and complete gate output are
recorded on #169 and in the local `verify-head.log` handoff artifact.

The final head gate uses the compact owned fixture root, CPUWeight=10000,
RUST_TEST_THREADS=4 and unique TRACER_TEST_PORT=4389. The unchanged three-sample
RTT self-test runs on the booked VM through `rt-timing-gate-wrapper.py`, with the
normal Nix Python preserved for other scripts. Final branch verification and
push status are recorded on #169. [Author checklist](reviewer-checklist.md).

## How to test the later UI pass

1. Add an isolated host whose private setup marker and inode-bound fresh
   journal own closed canonical session sockets. Expect the exact title/body
   from `contracts/ssh-bootstrap.md`, primary “Start fresh”, secondary “Back”.
2. Start fresh: expect the same attempt to continue and finish. Paths appear
   only in Details. A live socket/process/lock offers to wait.
3. Add a foreign root or lock file: every file and socket remains untouched;
   unsupported older journals show the fixed refusal reason. Owner live
   fixtures are reserved for the owner to test from the product.
