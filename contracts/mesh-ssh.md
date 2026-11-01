<!-- Freezes the mesh SSH adapter and its shared identity/runtime boundaries [D235,D289], #221. -->
# SSH over the mesh

This contract defines SSH behavior and interfaces for #221. D289 selects
russh 0.64.1 with ring and russh-sftp 3.0.1. The embedded server remains
unavailable in component actions until Q14 is met. S0 recovers and reconciles
the implementation without binding a port, starting a listener, or enabling
mesh SSH.

## Product behavior and consent

- `infraternal ssh <machine>` always opens a shell.
- `infraternal open <machine>` opens or focuses that machine's screen in the
  infraternal web app's canvas when app windows are enabled. A headless machine
  or one with nobody logged in to its desktop falls back to a shell with an
  explanation. The app path prints one line in the terminal and exits.
- If either one-off shell drops, print a recovery handle and an explicit resume
  command. `--json` returns a finite JSON result; reject interactive TTY
  streaming with a useful message instead of wrapping it in a JSON envelope.
- Approved add-host/up and visible per-host Login access are standing consent.
  An unattended target does not need to approve each connection. A machine's
  ownership does not grant access to arbitrary target accounts.
- Every new shell or file open must pass Network access for the source machine
  to the destination's exact mesh-IP:22 and shared Login access for the person
  to the requested OS account. Login access applies to every shell and file
  entry point in the same release; SSH remains unavailable until Q14 is met.
- During a partition, the last-applied access rules remain usable. The person
  can see their revision and coverage are stale. Certificate expiry by itself
  does not disconnect an allowed live session; revocation or narrowed access
  ends affected sessions. Audit pressure warns, buffers within a fixed bound,
  and exposes a visible gap count.

## Identity, keys and host trust

The client uses hidden per-person SSH keys. The infraternal agent creates each
key in the Secure Enclave or TPM when available, otherwise in memory. The
person approves its use once with a passkey. A 24-hour certificate renews
silently. Keyless machine-identity authentication is rejected for a person's
session because it cannot distinguish people sharing a client machine. No
`~/.ssh` key or configuration handling and no host-key prompts are part of
this flow; managed host trust vouches for the target. The minimum supported
stock client is OpenSSH 8.0. A target's own OpenSSH authentication remains
separate when that service is reachable.

Authentication uses a verified person certificate or an explicit machine
identity. No infraternal mesh login is accepted through `authorized_keys`.
The protocol adapter verifies the certificate signature, issuer, type,
critical options, principal, proof of possession, validity interval, source
node/address and current person/link state. An invalid certificate is never
retried as an ordinary key. A certificate authenticates a person; it does not
replace either Network access or Login access.

SSH-specific signing stays under the existing protected signing authority.
The adapter must not export CA key material or introduce a second ordinary
memory signer. A local signing request is bound to the requesting process and
the current session identity. Forwarded signing requests are refused by
default and require an explicit per-rule grant.

## OpenSSH-equivalent operations

The product supports local, remote and dynamic port forwarding (`-L`, `-R`,
`-D`), rsync, scp and SFTP; command execution and exit status; signals and
terminal resize; environment and locale; and managed host trust. These are
part of the contract even where S0's recovered adapter does not yet implement
them. Agent forwarding (`-A`) is also in product scope, off by default, and
allowed only by an explicit per-rule grant. No default or implicit grant may
enable it.

Prompt and scale targets for the fully wired product are about 0.3 s on a LAN
and 1.5 s at 150 ms RTT, with first-login/link setup reported separately. Size
and lifecycle checks cover 50 simultaneous sessions as the typical case and
500 as the stress case. The first canary is perf-01; the dev VMs go last.
These targets do not authorize S0 to enable the listener.

## Production interfaces

The protocol adapter lives in `crates/plugins/ssh/src/mesh_*.rs` and owns no
access rules, OS login database, shell process or daemon filesystem
credentials. `mesh_login::LoginAuthority` provides the shared current
authority; `LoginGuard` verifies a person/account and registers a shell,
command or file attachment in the shared person/account runtime while the
same guard is held. Each channel or file open rechecks current access and
certificate identity. A person cannot be rebound to another person when a
certificate has several signed principals. Revocation retires affected
attachments. Protocol callbacks never wait for account or filesystem work.

The runtime opens and files belong to the target OS account through the
existing infraternal agent and shim session lifecycle. SSH attaches to that
runtime; it does not create a second shell tree or perform target-user file
operations as the daemon. The adapter is disabled until both the shared Login
access authority and the per-person runtime are available. Test authorities
and runtime doubles prove adapter behavior only, not production integration.

### Dependency map

| Issue | Owner and current path | SSH boundary |
| --- | --- | --- |
| #186 | The production all-shell Login access evaluator is absent from current `dev`; the existing server auth modules in `crates/infraternal-server/src/auth/` do not provide it. The recovered adapter seam is `crates/plugins/ssh/src/mesh_login.rs` (`LoginAuthority`, `LoginGuard`) with certificate/network admission in `mesh_admission.rs`. | Implement one shared server evaluator for all shell and file opens, then supply its current authority and guard through the adapter seam. SSH adds no evaluator, access list, or second source of truth. Q14 requires every shell and file path to use the shared implementation. |
| #172 | Person/account login lifetime and OS session creation: `crates/infraternal-agent/src/{daemon.rs,lib.rs,login_auth.rs,login_binary.rs,login_records.rs,logins.rs,rootless_sessions.rs,sessions.rs}`; `crates/infraternal-shim/src/{child.rs,cleanup.rs,lib.rs,login.rs,login_handoff.rs,login_ready.rs,pty.rs,session.rs,shell_startup.rs}`; server account selection/revocation in `crates/infraternal-server/src/{bootstrap_remote.rs,embedded.rs,lib.rs,plugins.rs,preferred_accounts.rs,remote_guard.rs,websocket.rs,websocket/login_preparation.rs}` and `crates/infraternal-server/migrations/0032_preferred_accounts.sql`; SSH account selection in `crates/plugins/ssh/src/accounts.rs`; command wiring in `crates/infraternal/src/{cli/actions.rs,main.rs}`. Migration 0032 follows current `0031_terminal_startup_hints.sql`. | Supply the target-account shell/file runtime. It does not decide Login access. Reconcile only these paths onto current agent, shim and server behavior; preserve unrelated current code. |
| #205 | Optional `process-per-user` terminal-memory implementation in `crates/infraternal-shim/src/{terminal_memory.rs,terminal_native.rs,user_host.rs}`, consumed by `terminal.rs` and `ring.rs`; opt-in features are declared by the shim and CLI crate manifests. | This is a memory optimization, not identity, access control or the session spawner; it remains off by default and SSH correctness cannot depend on enabling it. |
| #220 | Mesh path state is represented by `crates/infraternal-mesh/src/backend.rs` (`PathKind`); current mesh data paths are owned by the existing mesh plugin under `crates/plugins/mesh/src/`, including `dataplane.rs` and `wireguard.rs`. | The SSH listener consumes a stream supplied by the existing mesh lifecycle. It adds no path selector, observer, or second mesh route. |

## Transport and resource ownership

The transport adapter uses consumer-acknowledged byte credit and bounded byte
buffers. It returns credit only after the runtime accepts input, keeps control
progress available while output is blocked, and pauses slow transfers rather
than growing a packet-count queue. SFTP work and the SSH connection future are
owned by their attachment; cancellation retires that work. The shared shim
session keeps its normal detach and reattach lifetime.

The listener binds only an applied mesh address on TCP/22, for IPv4 or IPv6.
If the exact bind reports address-in-use, an owned redirect scoped to the mesh
interface may select an internal listener only after tests prove original
destination-port enforcement, cleanup and acceptable latency. An internal
port is never an additional Network access permission. No wildcard or loopback
listener, host sshd edit, host-wide firewall flush or host sysctl change is
allowed. Published underlay traffic rewritten onto a mesh address remains
refused; node-local delivery remains supported.

Installation and removal are atomic. A same-named table without the exact
ownership marker is foreign and cannot be adopted, replaced or removed. Stop
removes owned rules before releasing the listener; failed cleanup stays
visible and retryable. Restart recovery handles retained rules before new
sessions are admitted. Abrupt process exit is not proof that rules were
removed.

## Recovery provenance and gates

The transport source is immutable commit `68caff92a3acefd801739895a48eece699971348`,
reviewed at `b8211e742f78b440c659e2aa81439e7b728b1084`. It was based on
`650472b987dbd1fe7192248dd1367d0766c5fb79`; its historical tree is not merged
wholesale. Recover only the reviewed mesh adapter/port implementation, its
required pinned russh/ring/SFTP sources and notices, and focused transport and
original-port regressions. Preserve current host SSH setup, mesh state,
firewall implementation and build tooling.

The login source is immutable merge `86045327b84a018cfb5c427ff9b05b897d020106`,
based on `b231301396227821a992692410cf55c50abe04ef`. Port only the
person/account runtime paths into current agent/shim code, preserving current
features and decisions. Research harnesses and stale build tooling are not
production paths. Its preferred-account migration follows current migration
`0031` as `0032`.

MSR-01 through MSR-06 remain required regressions. Scoped checks cover the
real russh engine and stock clients, bounded input/output and control
progress, certificate identity and revocation, file-worker cancellation,
port ownership and original-port enforcement. These tests use test authority
and runtime implementations until the shared #186 and #172 production paths
are integrated. Their success does not enable SSH or satisfy Q14.
