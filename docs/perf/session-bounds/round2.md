<!-- SB-01 repair, retention invariants, real-engine regression and scale evidence for #151, D13/D41/D214/D218. -->
# Final output after credit starvation

The unchanged independent-review regression was cherry-picked first at
14c13138. Its Rust test blob remains
`a9f392314c16dac342334398f4e4b7e40e403d02`. The round-one executable reproduced
Close(1, "terminal shim disconnected") after the actual 250 ms shim data-link
detach. The repaired executable delivers `FINAL_OUTPUT` and exit status 7.

An authenticated ownership-only shim connection now survives data-link credit
starvation. Its negotiated capability is additive; a shim that does not
advertise it receives no extra connection. Ownership is installed before data
replay using the existing frozen InputState exchange. The connection consumes
neither PTY output nor a sequenced-input writer slot. The relay releases it only
after the ordered exit Event writer acknowledgement, or when its window closes.
Several windows hold separate ownership connections; releasing one does not
release another's session.

An exited shim has a one-shot **600-second** maximum, starting at observed child
exit. Reconnecting cannot refresh it. Ten minutes covers ordinary short mobile
network/credit interruptions while bounding retained exited processes and their
ring/history memory. Keeping every exited owner indefinitely would recreate
#151; retiring at the 250 ms credit-detach would lose the final screen again.
There is no retention timer for running idle shells. With no owner and drained
output, retirement is prompt as before.

Before retiring, the shim atomically publishes a private 17-byte runtime exit
record containing the frozen Exited frame. Reading requires a regular same-UID
0600 file, rejects symlinks, validates the exact length and uses the existing
fuzzed decoder. It stores status and final sequence, never terminal content.
After the bound, replayed output is no longer available: attachment returns the
recorded `terminal.exited` Event then shared Close(4404, "session ended"). That
type comes from the concurrent fix-dead-session protocol change, a93942d6.
Unknown sessions get the same typed Close with no invented status. Records
survive daemon restart within the runtime directory, not host reboot; runtime
file cleanup remains separate from retained shim-process bounds.

## Real-engine evidence

`scripts/verify fast` passed 578 workspace tests (62 existing ignored tests).
The unchanged review regression passed; real retention tests cover forced
retirement, exit status 7 on next attach after daemon restart, and a usable
sibling/control channel. All 13 real-shim tests pass, including no-owner exit,
owner release, maximum retention despite an unread data peer, and two owners.
Author review also reproduced retirement publication before listener teardown.
With the real exit record and a private same-UID socket closing handshakes,
the prior artifact failed daemon restart with `unexpected end of file`. Fixing
recovery alone then reproduced Close(1, "terminal shim disconnected") on attach.
Discovery now ignores a failed handshake only when a secure verified record
proves the UUID ended. A relay error boundary returns that recorded status for
failures in Hello, owner confirmation, input-state recovery or steady-state
reads. Unknown/insecure records preserve strict errors. Successful connections
perform no extra record read. The expanded real-retention regression passes;
its red logs are `round2-retirement-race-before.log` and
`round2-retirement-race-recovery-only.log`.

The final Rust gate output is:

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

The static-size row is the existing historical-limit exception. Final x86 musl
is **19,699,392 bytes**, up **43,072 bytes (0.219%)** from round one's 19,656,320.
It is stripped static PIE with no PT_INTERP; SHA256
`b1c8fcface143e0d2e0dae4fde67c2076106fedfdcadc52e671a8364e03833f4`.
A separate locked ARM musl build completed in 5m 15s: **17,570,744 bytes**,
up **36,784 bytes (0.210%)** versus round one's 17,533,960. It is stripped,
statically linked with no PT_INTERP; SHA256
`96687aa0d81b0863534d796f484646cce8deacd8a66076b746f6b99557683a6a`.
Both artifacts are preserved in the scratch `artifacts/` directory.
No dependency or foundational engine was added. The gate stops at that size
failure, so its skipped TypeScript half was run separately and passed compiler,
UI tests, production build, transfer budget and 36 protocol tests (34,462
assertions). Critical transfer remains gzip 288,093 / Brotli 239,205 bytes.

The concurrent-owner-aware AckBarrier fixture preserves the actual data oracle:
24 restart positions recovered 4,710,396 exact bytes; the written/accepted
barrier observed 14,138 / 524,602 bytes and replayed 524,288 exact bytes. Twelve
streams each recovered 65 queued inputs, 2,640,000 total exact bytes. A sibling
and control path stayed responsive at 303.790 ms with the 300 ms network profile.
Idle daemon and attached shim each scheduled zero slices over 2.2 seconds.

## Scale and latency

`measurement-round2-200.json` preserves the final binary hash and all raw rows.
The local weighted run used infraternal-dev (8 cores, 32,803,748 KiB RAM),
80x24 real shells and 12,000 history rows each; no own build/browser or synthetic
CPU load ran during the measurement. Initial load was 23.58/26.49/27.21; filled
sample load was 44.38/31.13/28.72. Recovery found 200 sessions, admitted 201 and
returned to 200 after prompt retirement.

| Phase / role | PSS KiB total | Private dirty KiB total | Mean PSS KiB |
| --- | ---: | ---: | ---: |
| Empty / shim | 217,816 | 213,616 | 1,089.08 |
| Empty / shell | 122,109 | 118,888 | 610.54 |
| Filled / shim | 3,578,700 | 3,574,500 | 17,893.50 |
| Filled / shell | 134,147 | 130,888 | 670.74 |

Combined empty PSS is **339,925 KiB**, +586 KiB (0.173%) versus round one.
Combined filled PSS is **3,712,847 KiB**, +2,113 KiB (0.057%) versus round one. Holding 200
ownership links added no measurable resident pages. Releasing them left shim
totals unchanged; filled-shell PSS varied by 9 KiB. These page-granularity
samples do not assert zero descriptor or heap cost. At 200 owned exited shims,
retaining the same state for up to 600 seconds implies approximately 217,816
KiB empty or 3,578,700 KiB with the measured filled history, before shell
exit removes the shell share. Admission retains the existing memory floor. Each shim retains one thread
and a 48 KiB resident stack. Host-facts latency at 200 sessions with the existing
300 ms network profile: median 309.192 ms, maximum 336.490 ms, 31 samples.

The weighted x86 musl release relay diagnostic (`relay-memory-round2-200.json`)
measured a 2,552-byte future and 1,448 KiB private growth for 200 actual relay
futures with paired authenticated Unix fixtures: 7,413 bytes per stream,
including fixture overhead, at load 24.53/28.22/28.55. That is below the 32 KiB
allowance by 4.4 times and totals below the 4 MiB connection reserve. The prior
GNU diagnostic reported 1,728-byte futures and 1,004 KiB growth; differing libc
and test linkage limit causal attribution of the private-memory delta. These
legacy-capability fixtures do not install owner links; the separate real-shim
measurement includes 200 ownership links. No PTY memory is attributed to this
transport diagnostic.

The zero-network, quiet real-shim attach acknowledgement comparison used
51 samples each at load 44.38/31.13/28.72. Round one measured median 0.247676 ms,
maximum 3.341133 ms; round two measured median 0.468064 ms, maximum 4.656156 ms.
The observed median increase is 0.220388 ms per attach. This includes ownership
installation and input-state recovery; it does not measure repaint or replace
D41's end-to-end budget. Host variation limits causal attribution. Reproduce:

```sh
INFRATERNAL_TEST_RTT=0 systemd-run --user --scope -p CPUWeight=10000 python3 scripts/measure-session-attach.py --binary /absolute/path/to/infraternal --samples 51
systemd-run --user --scope -p CPUWeight=10000 python3 scripts/measure-session-memory.py --binary /absolute/path/to/infraternal --sessions 200 --owners
```

Production real-server specs ran against the production tracer build, unique
ports and weighted local scope. The full run had **38 passed, 3 skipped, 3
failed** in 12.1 minutes: thumbnail scale was 0.697676 versus <0.58, low-memory
refusal timed out, and Mesh bulk enrollment had two refused calls. No browser
assertion or timing budget was changed. The same three files passed against
round one's executable (6 passed, 2 skipped, 48.3 seconds), then against the
pre-race round-two executable (6 passed, 2 skipped, 43.7 seconds). Thus all **41
non-skipped specs** have passing evidence across the full run and isolated
rechecks; a single fully green 44-spec invocation is not claimed. The transient
full-run failures remain in `round2-server-specs-weighted.log`, with comparisons
in `round2-browser-three-baseline.log` and `round2-browser-three-final.log`.
Two further full runs retained timing failures: one overlapped own ARM build
(33 passed, 3 skipped, 2 failed, 6 not run); one had no own compilation but host
load rose from about 8 to 43 (38 passed, 3 skipped, 2 failed, 1 not run).
A round-one prefix comparison also failed the 4x-CPU frame-count assertion
(16 frames versus >20), with 10 passed and 2 not run. These logs remain
`round2-server-specs-final.log`, `round2-server-specs-quiet.log` and
`round2-browser-prefix-baseline.log`. No frontend behavior or fixture threshold
was changed to make the production checks pass. The final race-fixed executable
also passes all five production bootstrap/sign-in/window-routing/close/reload
flows in 18.1 seconds (`round2-browser-final-functional.log`, unique port 4367).

Production screenshots are written under
`$HOME/.cache/codex-scratch/session-bounds/evidence/`, including phone keyboard-up/down,
host facts, Mesh and sidebar states. Attach requested images to #151 with the
orchestrator's `issue-attach` helper. This backend repair changes no frontend
layout. Browser plugin tools were unavailable, so the repository Playwright
harness supplied the real-server evidence. This job does not judge screenshot
quality.

## Author review

Reviewed additive capability negotiation, ownership installation and release,
separate data/ownership backpressure, multiple owners, nonrenewable deadline,
no idle timer for live shells, ordered Event-before-Close status delivery,
restart recovery, retirement publication before listener teardown, handshake
and relay error recovery from verified records, path/UID/mode/length checks
and fixed-frame decoder reuse.
Existing admission, input sequencing, process identity, plugin boundaries and
UI component reuse remain covered by the workspace and production checks.
Independent review still owns the visual judgment and final verdict.
