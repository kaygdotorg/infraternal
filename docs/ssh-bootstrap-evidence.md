<!-- SSH bootstrap implementation, measured component evidence and explicit acceptance prerequisites; #87. -->
# SSH bootstrap evidence

This branch supplies a strict system OpenSSH adapter, memory-only credential
helpers, transactional installation and owner-authenticated progress. Full
end-to-end acceptance is incomplete: production enrollment, authenticated facts
and terminal routing must be supplied by #78, with verified plain OpenSSH trust
and authentication for o1/o2. The default server runner fails before upload.

## Runtime and contract

`/v1/bootstrap/ws` requires the pinned Origin and one unlocked owner cookie.
Start accepts up to 100 unique target ids; invalid admission is refused before
SSH. Runtime failures remain independent under eight globally active hosts.
There are 16 socket/batch slots, 1024 replay events and at most eight attempts per
host. Ping/Pong preserve progress without refreshing authority. Revocation
interrupts even a stalled write; disconnect cancels work and runs rollback.

The ordinary server now mounts the router. Before registration, a real TCP
regression returned 404 instead of unauthenticated 401; its corrected result is
in evidence/ssh-bootstrap/continuation-runtime-route-green.log.

The trusted factory receives the exact live Auth and SQLite pool. Backend
operations receive nonsecret owner/batch identity and an opaque zeroizing
session capability; it has no Debug/serialization. Production enrollment must
atomically recheck that exact live session. Reserve a host attempt through readiness or cleanup,
associate new authority with this batch, and preserve prior authority during
failure cleanup even after logout. Facts and terminal proof must use this
attempt's authenticated certificate/generation, not an old host connection.

Map root to #78's `rootful` and execution uid 0; rootless retains the observed
nonzero uid. Pass the settled invitation response unchanged on private stdin
(host_id,mode,execution_uid,token,ca_der,endpoint,server_name). Its lifetime is
900 seconds and single use; a locked CA fails before upload. Root consent is
independent of owner authority, sudo availability and CA unlock.

Set `INFRATERNAL_BOOTSTRAP_X86_64_BINARY` and
`INFRATERNAL_BOOTSTRAP_AARCH64_BINARY` to the matching final musl artifacts.
Default sibling names are `infraternal-x86_64-musl` and
`infraternal-aarch64-musl`; there is no fallback to a GNU server executable.
Default discovery and credential-vault adapters are unavailable. Production
vault resolution must use the existing passkey encryption and return decrypted
material only for its attempt; the transport accepts no plaintext HTTP fields.

Direct SSH preserves server config, known_hosts and existing identity in place.
ProxyJump/ProxyCommand configurations are refused because outer strict options
do not protect every child hop. Host-key observations are untrusted data and
never write a trust store. Password/key-passphrase helpers refuse trust and
permission prompts. Rootless requires an available systemd user manager;
request own-user linger only through noninteractive host policy, without sudo.
Denial produces a warning; rollback reverses only a newly enabled setting.

Data is under D17, with a private owned 0700 root. SHA256 verification precedes
execution. Upgrade only recognizable bootstrap-owned layouts; refuse unrelated files
and units. Keep prior binary/state/unit until authenticated readiness. Rejoin
copies existing identity only inside its private host-local transaction; no
host private key crosses SSH. An active service must acknowledge stop before
replacement. Interrupted rollback retires mutation markers before restoring
originals and can resume link restoration with fresh credentials. Foreign
files/locks remain untouched. Cleanup coordinates are in batch memory; a
process crash or unreachable host can require operator recovery of a stale
transaction. Running-daemon handoff and actual operator-join compatibility
still require #78 integration tests.

## Measurements

All measurements run on infraternal-dev, Linux x86_64, 8 logical cores, under
`systemd-run --user --scope -p CPUWeight=10000`. They are component diagnostics,
not unloaded pinned performance gates. No perf VM was used.

| Real rootless sshd component | Result |
| --- | ---: |
| Credential/config preparation | 23884 us |
| One read-only system check | 118522 us |
| Ten concurrent SSH check connections to one fixture, local | 180 ms |
| Same ten connections, 300 ms RTT with ±30 ms jitter | 2602 ms |
| Controller RSS local baseline/peak | 4772/4828 KiB |
| Controller RSS delayed baseline/peak | 4828/4840 KiB |
| Owned SSH child summed RSS local/delayed peak | 91432/91476 KiB |

Initial load 1.44/1.37/1.27; `evidence/ssh-bootstrap/continuation-real-ssh.log` includes one passing
real-sshd oracle, strict unknown-key rejection at the configured port and
credential-helper cleanup. Child RSS repeats shared libraries and excludes the
fixture's sshd/ssh-agent, database, authentication and full control-plane state.
The ten connections are not ten distinct full host installations.

A controlled backend admission run held 1000 targets in 10 batches at exactly
eight active operations: baseline/held/completed RSS 4432/7452/7884 KiB, 45 ms to
independent failure. It measures scheduler state, not whole-server memory.
Load 0.69/1.10/1.19; evidence/ssh-bootstrap/continuation-admission-scale-final.log
records the current production scheduler, with a controlled unavailable backend.

Inherited-run private-directory checks, 500 interleaved samples/profile, initial
load 1.84/1.75/1.70: plain shell p50/p99=1002/1506 us; equivalent two-fork
ownership/mode guard 3827/5791 us; one-fork guard 2521/3593 us. Retain builtin owner
checking plus one stat, saving 1306 us median. Added 1519 us/script is justified by
rejecting writable/foreign identity roots; SSH and complete phase times are
excluded.

Inherited ASan campaigns exercised 5,512,158 and 1,467,476 parser inputs in
61 seconds each without a crash. The extended campaign covers allowlisted
diagnostics and seeds through 65537 bytes. Instrumented fuzzer memory is
not server memory. A subsequent run linked directly to the production crate exercised
1,366,902 inputs in 61 seconds without a crash, through the same target source.
The continuation campaign ran 4,256,482 executions in 181 seconds, max_len
65537, seed 1694043920, without a crash (continuation-parser-fuzz.log).
After two Clippy-only assertion/style corrections, the final source completed
100,000 more executions in four seconds without a crash
(continuation-parser-final-source.log). Both logs are under evidence/ssh-bootstrap/.

The subprocess group-lifetime regression first demonstrated a reaped leader
while inherited pipes remained pending. Retain its unreaped identity until
I/O completes, then reap/disarm without an intervening await. A 500-sample
interleaved helper-completion diagnostic recorded original p50/p99
767/1181 us and revised 762/1179 us, initial load 2.16/1.74/1.60. It does
not force PID reuse or demonstrate an unrelated-process kill.

The SSH candidate comparison is in `research/ssh-client/REPORT.md`: 25 samples
per RTT profile and 200 retained connections, memory multiplied by 200, isolated
binary-size delta, license and trust/config parity. No engine switch is made.

The final reachable production binaries measured 16,520,048 bytes x86_64 musl
and 13,881,064 bytes aarch64 musl, stripped and without PT_INTERP. The unchanged
262,144-byte allowance passes against the separately recorded #87 baselines.
Evidence: evidence/ssh-bootstrap/continuation-runtime-fast.log.

## Real-host prerequisites and remaining acceptance

Inherited read-only, strict NetBird checks on o1 (10.69.69.51) and o2 (10.69.69.52) confirm
Linux/aarch64/systemd, uid 1002, sudo=no, user manager=yes, linger=yes and no
existing installation. Plain OpenSSH refused their unverified ED25519 trust.
No host key was accepted or modified; neither host was installed or changed.
The continuation contacted no named remote host: local installation/terminal proof has
not passed, so its o1 installation prerequisite is unsatisfied.

Owner/orchestrator must provision verified plain OpenSSH known_hosts and usable
authentication outside this job. The committed remote-agents branch at c0815d2 still lacks production operator
CLI activation and remote terminal runtime; #78 comments describe that work as
uncommitted. After it provides join/listeners/routing and integration adapters,
first run a disposable local rootless installation through the server,
confirm authenticated facts and a terminal, uninstall every placed artifact,
and record check/install/facts/connect timings. Only then attempt o1 using
preexisting verified trust, and remove its installation afterwards. Measure ten
distinct full local targets, the 300 ms profile and whole-server memory. These requirements are not
satisfied by fixture checks, token redemption or component gates.

## How to test

1. Use the pinned Origin and an unlocked owner cookie to open `/v1/bootstrap/ws`;
   send the start/retry/replay shapes in contracts/ssh-bootstrap.md.
2. With the default runner, manual checks can run but enrollment fails before
   upload; vault/discovered-host references also fail without network mutation.
3. For full installation, provide the #78 trusted runtime factory first; confirm
   current-attempt facts and terminal proof, then remove every test artifact.

## Reviewer checklist

| Area | Evidence / limit |
| --- | --- |
| Consent/admission/owner/origin/cookie | Production validators and software-passkey real TCP tests |
| Live authority and revocation | Exact session capability, atomic backend requirement, stalled-write/idle logout tests |
| Strict keys and in-place identity | Real sshd unknown-key oracle; real config proxy refusal |
| Secret lifetime and prompt policy | Real hidden CLI password/encrypted-key handoffs, owned 0700/0600 fixtures; no secret argv/files/logs |
| Transaction and recovery | Real-files policy, foreign-root/lock, identity, stop failure and interrupted-rollback regressions with a synthetic manager/CLI |
| Work bounds / isolation | Ten-target unit cohort;1000-target controlled scale; ten real SSH connections |
| Parsers | ASan fuzz target covers check/config/destination/policy/diagnostics, seeded through 65537 bytes |
| Static artifacts / licensing | Both musl targets, no PT_INTERP; full cargo-deny; isolated research cargo-deny also passes |
| Production remote readiness / uninstall | Unproven until #78 and verified o1/o2 OpenSSH prerequisites |
| Full phase latency / whole-server scale | Unmeasured; explicitly remains acceptance work |
| UI / visual review | No UI change in this lane |
