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
- The server's own host is no exception (owner, #221 Q-A (b)). Every node's
  implicit reach to the server (D164) covers only the infraternal control
  plane; TCP/22 there follows Access like on any other node: an explicit
  arrow toward the server, or the default. The server's node carries that
  answer per peer (`PeerPolicy::access_ssh`), and the default-policy preview
  lists the nodes that would lose it (`loses_ssh_to_server`).
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
stock client is OpenSSH 8.9 (raised from 8.0 in slice 1: see "Slice 1
threat model" below). A target's own OpenSSH authentication remains
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
the current session identity. Requests arriving through SSH agent forwarding
are always refused (D235): the infraternal agent never signs a forwarded
request.

## OpenSSH-equivalent operations

The product supports local, remote and dynamic port forwarding (`-L`, `-R`,
`-D`), rsync, scp and SFTP; command execution and exit status; signals and
terminal resize; environment and locale; and managed host trust. These are
part of the contract even where S0's recovered adapter does not yet implement
them. The infraternal key socket never signs a forwarded request (D235). The
owner decided on 2026-11-02 (#221 comment 74668) that `-A` should forward the
person's own agent; slice 1 does not do that yet (with `IdentityAgent` set,
OpenSSH forwards the infraternal socket, whose forwarded connections never
sign). Forwarding the person's own agent needs its own design.

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
| #172 | Person/account login lifetime and OS session creation: `crates/infraternal-agent/src/{daemon.rs,lib.rs,login_auth.rs,login_binary.rs,login_records.rs,logins.rs,rootless_sessions.rs,sessions.rs}`; `crates/infraternal-shim/src/{child.rs,cleanup.rs,lib.rs,login.rs,login_handoff.rs,login_ready.rs,pty.rs,readiness.rs,session.rs,shell_startup.rs}`; server account selection/revocation in `crates/infraternal-server/src/{bootstrap_remote.rs,embedded.rs,lib.rs,plugins.rs,preferred_accounts.rs,remote_guard.rs,websocket.rs,websocket/login_preparation.rs}` and `crates/infraternal-server/migrations/0032_preferred_accounts.sql`; SSH account selection in `crates/plugins/ssh/src/accounts.rs`; command wiring in `crates/infraternal/src/{cli/actions.rs,main.rs}`. Migration 0032 follows current `0031_terminal_startup_hints.sql`. | Supply the target-account shell/file runtime. It does not decide Login access. The rootless real-binary regressions live in `crates/infraternal/tests/agent_daemon.rs`, `scripts/test-rootless-*.py` and shared fixture support in `scripts/agent_fixture.py`; they exercise this runtime and do not implement SSH. |
| #205 | Optional `process-per-user` terminal-memory implementation in `crates/infraternal-shim/src/{terminal_memory.rs,terminal_native.rs,user_host.rs}`, consumed by `terminal.rs` and `ring.rs`; opt-in features are declared by the shim and CLI crate manifests. | This is a memory optimization, not identity, access control or the session spawner; it remains off by default and SSH correctness cannot depend on enabling it. |
| #220 | Mesh path state is represented by `crates/infraternal-mesh/src/backend.rs` (`PathKind`); current mesh data and service-policy paths are owned by the existing mesh plugin under `crates/plugins/mesh/src/`, including `dataplane.rs`, `wireguard.rs`, `firewall.rs` and its `iptables.rs` fallback. | The SSH listener consumes a stream supplied by the existing mesh lifecycle. The current firewall enforces the original service port across destination translation. SSH adds no path selector, observer, or second mesh route. |

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
port is never an additional Network access permission. It is a port only root
can bind (below the kernel's `ip_unprivileged_port_start`, read each time), so
a table left by an abrupt exit cannot hand mesh TCP/22 to a local account
(J236 P2-2). A rootless infraternal agent, or a host whose bound leaves no
such port, gets no redirect. No wildcard or loopback
listener, host sshd edit, host-wide firewall flush or host sysctl change is
allowed. Published underlay traffic rewritten onto a mesh address remains
refused; node-local delivery remains supported.

Installation and removal are atomic. A same-named table without the exact
ownership marker is foreign and cannot be adopted, replaced or removed. Stop
removes owned rules before releasing the listener; failed cleanup stays
visible and retryable. Restart recovery handles retained rules before new
sessions are admitted. Abrupt process exit is not proof that rules were
removed.

Stop is driven by the infraternal agent, not by `Drop`: the registry that owns
the component lives for the whole process. The component hands the agent a
stop hook (`infraternal_plugin_api::stop_hook`), and the agent runs it when its
work returns or when it receives SIGTERM (`systemctl stop`, or the server
stopping its embedded infraternal agent), within 1.5 s, then re-raises SIGTERM
(`infraternal_agent::shutdown`). After the hook starts, the component never
binds again. SIGKILL and a hook that overruns its bound still rely on restart
recovery.

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

## Slice 1 threat model and decisions (J175, J181 review, #221)

Slice 1 is the smallest end-to-end cut: a person's machine runs plain
`ssh`, the local infraternal agent signs with that person's certificate, and
the embedded server on the target's mesh address checks the certificate,
network access and login access. This table is what the code is reviewed
against.

| Attacker | Can | Stopped by |
| --- | --- | --- |
| Mesh peer without a person key, including a compromised node | Reach TCP/22 on nodes with mesh SSH on (network access is allow-all by default, D228 M2) and open connections. | Certificate signature, full-digest registry, `source-address` bound to one mesh address, both access checks on authentication and on every channel open. At most 8 unauthenticated connections per source node and 64 in total, a 20 s login deadline, and accept backoff when descriptors run out. |
| Same machine, the account the machine was added with | Signs as the person. Inherent to a key socket. | `source-address` and the certificate lifetime (24 h). |
| Same machine, any other account | Nothing: the key socket checks the kernel peer credentials on every connection and serves only the account the machine was added with (decision below). | `SO_PEERCRED` before any byte is read. |
| Same machine, root or a system account | Never acts as a person. Root can still become the person's account, so this protects against mistakes, not against root. | Ordinary-UID check. |
| Local user tampering with client files | Nothing: the `ssh_config.d` file and the known-hosts file are written only into directories owned by root and closed to group and other writes; the socket directory is checked the same way. | `trusted_directory`. |
| Stolen node (root on it) | Uses the in-memory person key until the node is removed; impersonates only its own host names. | Node removal pushes a snapshot without its digests; turning mesh SSH off for a node ends its open connections. |
| Compromised target | Sees a session-bound signature it cannot replay elsewhere. Cannot get a signature through agent forwarding. | The socket signs only on a connection that declared itself with `session-bind@openssh.com` without the forwarding flag (OpenSSH 8.9 and later); undeclared connections never sign. |
| Server code reaching the CA | Can issue only the two mesh shapes. | The CA module exposes `issue_ssh_person` and `issue_ssh_host` only; it checks the issued shape again itself and every issued certificate is recorded by digest. |
| Network partition | A node keeps its last snapshot; a revocation lands on reconnect. | The person certificate lifetime (at most 24 h) bounds the staleness. |
| Replayed or delayed push | Nothing: a node installs a snapshot only if its sequence is higher, and reports a refused one, so the server retries. The sequence is stored and never below the clock, so it survives a server restart. | Sequence check in `mesh_authority`. |

Decisions in slice 1:

- **Who acts as the person (D235 Q2a, D344).** Only the local account the
  machine was added with: the rootless execution account, or the user of a
  rootful machine's add-host address (narrowed by D347). Other accounts and
  root get no person identity.
- **The server's own host never acts as a person (owner, #221).** The server
  is not a place to work from: infraternal is heading towards an untrusted
  server, with the canvas running entirely on the client.
- **Push, not ask (owner question Q2 on #221).** The server pushes a
  sequence-numbered snapshot (CA key, valid certificate digests, each
  person's login grant for that host); the target checks network access
  against the applied mesh configuration the firewall enforces.
- **Signing key (Q1).** The D168 CA key signs mesh SSH certificates through
  the typed issuers only. Any future use of that key needs its own
  non-overlapping body prefix.
- **Off by default (Q4).** A node serves and signs only after the owner turns
  mesh SSH on for it. Turning it off, or the node leaving the mesh, ends its
  open mesh SSH connections; a renewed host certificate does not.
- **Authenticated sessions** use keepalives (15 s, 4 misses), not an idle
  timeout, so an idle editor is not ended.

Left for later slices: live revocation of running sessions for one person
(L2), IPv6 person certificates (L3), warnings about user `ssh_config`
overrides (L4), per-host snapshot contents (L5), measured lock contention
(L6), a neutral server banner (L7), reattach re-checks, Secure Enclave and
TPM keys, sign-in with a device code, SFTP and forwarding.

