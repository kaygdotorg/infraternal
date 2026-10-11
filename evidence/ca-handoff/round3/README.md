<!-- Records the CA-R1/CA-R2 fix-forward delta, subprocess evidence and author checklist [206][217], #154. -->
# CA handoff — round 3

Base: `1da307870ccb11e289d91edfefba705c71a2aa64`. The two original reviewer
patches were cherry-picked unchanged as `a1ee82a4` and `e8d4c260`; neither test
was weakened. Issue #154 records each pushed logical step.

CA-R1 resets child masks and all catchable dispositions at the existing audited
shim process boundary. Both Command/pre-exec and POSIX spawn use that policy;
the server's blocked reload mask remains unchanged. Launch audit covers SSH
bounded execution, connection and key helpers, embedded infraternal agents,
PTY shells, shim/init launchers, server installation and remote removal helpers.
The server directly reuses its existing transitive shim dependency even when
`remote` is disabled; CA handoff storage still requires `remote`.

CA-R2 opens the candidate inode with `O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC`,
fstats and refuses non-regular/untrusted inodes before any read, then clears
only `O_NONBLOCK`. Ownership, protected-parent checks, close-on-exec, pinning
above standard descriptors and single-inode execution remain intact.

## Evidence

The original SSH reviewer regression fails in 0.13 s; the original FIFO
regression fails at its 3-second watchdog in 3.06 s. After repair, all five SSH
process tests pass, and all 16 restart tests pass in 6.27 s. The real subprocess
fixture verifies ignored dispositions, both spawn adapters, and parent-mask
preservation. Standalone embedded tests pass 15/0 (one ignored scale diagnostic),
sessions pass 6/0 (one ignored diagnostic), remote component tests with the
node-side feature enabled pass 12/0. Real SSH authentication and the physical
connection-reuse/helper-retirement oracle both pass with memory-only synthetic
keys. The latter fixture initially exceeded the Unix-socket path limit; only
its job-local path was shortened, without changing the test or product.

The stripped x86 shipping binary also passes the explicit rootless shipping
integration (0.83 s), retaining cold reply/state, PID, null input
and service behavior on reply failure. The remote-disabled top-level build and
supplemental TypeScript/compiler/production-bundle gates pass.

Initial FIFO compilation lacked `make`; the documented Nix build shell supplied
it. A standalone server build caught a missing optional direct dependency before
the embedded wiring was committed; the feature-independent process boundary is
now directly available. Failed attempts remain in the accompanying transcripts.

## Author checklist

- Post-fork reset contains only stack storage and async-signal-safe syscalls;
  it allocates no captured state and takes no locks. Dispositions reset before
  unblocking. Uncatchable signals are excluded; libc-reserved signal numbers
  may report `EINVAL`. Other syscall errors refuse exec.
- POSIX attributes preserve existing flags while adding mask/disposition reset.
  Existing descriptor actions, explicit stdin, process groups, cancellation,
  authorization and helper retirement remain unchanged.
- Reload ownership and early-startup ordering remain in the parent. Default
  child signals are independently exercised through real exec and POSIX spawn.
- FIFO refusal uses the opened inode, avoiding a pathname precheck race. No
  ELF/signature/read path runs before regular-file validation. Clearing the
  nonblocking status preserves all other flags and the same descriptor.
- The shared boundary uses only existing workspace libraries. Remote handoff
  state remains build-removable; the reset adds no task or timer. Transient
  Command callback allocation and fork cost are not total child RSS measurements.
- Existing CA parser/property/fuzz code is unchanged. This delta adds no parser,
  key export, key storage, authentication mechanism or dependency version.
- No UI changes, deployment, price, credentials or private-key fixtures are
  introduced. Independent delta review remains required by PROCESS §2/D206.

## Reproduce

Run `scripts/verify fast` with a job-local target directory and short fixture
root. Run the two unchanged review-test names from the brief to isolate the
regressions. Run the ignored shim spawn diagnostic in a local CPUWeight=10000
scope without overlapping this job's builds; its batches use 128 real children.

## Startup cost and binary size

Local CPUWeight=10000 scope on infraternal-dev, 8 logical CPUs, Intel i9-9900K,
Linux 6.12.111+deb13-amd64; pinned Rust 1.99.0/Zig 0.15.2. No CPU generators or
external performance hosts were used. The final diagnostic ran without this
job's builds overlapping it. Seven alternating batches of 128 real children:
baseline/reset batch median 204.024/277.006 ms, observed +570.173 us per child,
+72.982 ms across 128 launches. Load before 8.87/13.04/17.37, after
9.92/13.19/17.40. The earlier run observed +362.988 us per child; differences
between load windows are not an isolated causal estimate.

This bounded startup cost restores required default child signal behavior.
Steady session processing performs no reset. The diagnostic's zero idle/retained
fields describe reset-owned persistent state after each Command is dropped;
they are not measured total child RSS. Transient callback allocation and fork
memory are not included. See [final diagnostic](spawn-cost-final.log).

| Static target | 1da30787 bytes | Round 3 bytes | Delta |
| --- | ---: | ---: | ---: |
| x86_64 musl | 19974896 | 19976240 | +1344 |
| aarch64 musl | 17796824 | 17798168 | +1344 |

Both artifacts are stripped/static with PT_INTERP absent. Base sizes are already
recorded at 1da30787 in [round 2](../README.md). No size budget, release profile
or dependency version changed. ARM was built separately because fast exits its
static row at the known x86 ceiling. [Size observations](sizes.txt).

## Final gate

All ordinary workspace tests pass, including both review regressions and earlier
CA handoff tests. No #118 baseline exception was used. Supplemental TypeScript
checks pass (144 unit/tracer tests, 36 protocol tests and production bundle
checks); the top-level remote-disabled build passes. The rootless shipping test
was explicitly executed. Existing unrelated ignored diagnostics remain ignored;
the round-2 root 25-replacement scale proof was not rerun for this delta.

`scripts/verify fast` exits 1 solely at the known static size ceiling. Verbatim
summary from [final raw gate](fast-final.log):

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

Before/after kernel regressions: [SSH before](signal-before.log),
[SSH after](signal-after.log), [FIFO before](fifo-before-retry.log),
[restart suite after](restart-after.log). Additional real-engine and feature
checks: [helper adapters](helper-test.log), [real SSH auth](ssh-auth-real.log),
[connection reuse](ssh-single-real.log), [embedded](embedded-after-retry.log),
[sessions](sessions-after.log), [remote component](remote-agent-after.log),
[remote disabled](remote-disabled.log), [shipping](shipping-rootless.log),
[shipping audit](shipping-server.log), [ARM](arm-static.log),
[TypeScript](ts-fast.log), [machine](machine.txt).

The failed missing-build-tool, long-fixture-path and initial optional-dependency
attempts are retained with the other transcripts. No secret fixture files or
private-key material are archived. Implementation source head:
`a71b3315e9a6c57f489a5c347150cad888a94f3b`; documentation/evidence adds zero
binary bytes.
