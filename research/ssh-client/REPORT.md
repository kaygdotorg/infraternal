<!-- SSH engine research for owner choice: measured alternatives, trust semantics and limits; #87, D4/D141/D167/D170. -->
# SSH client measurement

> Historical raw receipts were removed under D262. The measured results remain; fresh output
> belongs under `$HOME/.cache/codex-scratch/ssh-client-research/evidence/` and selected files
> should be attached to #87 with the `issue-attach` helper.

The product adapter remains system OpenSSH. This report measures russh 0.63.1;
it does not select another foundational engine. The research package is isolated
from the product workspace, uses AGPL-3.0-only, and pins its separate lockfile.

## Method and environment

infraternal-dev, Linux x86_64, eight logical cores, OpenSSH 10.0p2 Debian,
Rust 1.99.0, release opt-level3/LTO/one codegen unit/stripped. CPUWeight10000
user scope. Initial load average 2.01/1.83/1.52. The repository runtime fast gate, including static
release builds, ran concurrently; these are diagnostics under that recorded load,
not an unloaded acceptance benchmark. The raw measurement receipt was removed under D262.

A real rootless sshd listens only on loopback. Fixture host/client private keys
are generated in memory; the host key uses an anonymous memory descriptor, the
client key enters ssh-agent or the probe on stdin. Only generated public trust
and configuration are files. No real identity is copied or inspected. The
harness stops its processes and removes its fixture after every run.

These are real TCP/SSH fixture-path numbers, not authentication measurements
on o1. Production-path comparison remains unavailable: previous strict
OpenSSH checks on o1 (10.69.69.51) refused its unprovisioned host key. No key
is accepted, copied or replaced to obtain a benchmark. Once the owner supplies
verified trust and #78 integration, measure the actual authorized path.

Twenty-five connections per candidate/profile measure connect through successful
public-key authentication, excluding remote command execution and installation.
The existing rootless relay adds 300ms RTT with ±30ms jitter per burst. OpenSSH
uses its normal defaults and russh uses its defaults; negotiated algorithms and
implementation scheduling are part of this comparison, not held constant.
No connection multiplexing is enabled. The retained-memory run opens 200
connections at local RTT, keeps all alive, and excludes sshd server processes.

## Results

| Client | Local authentication p50 / p99 | 300ms RTT authentication p50 / p99 |
| --- | ---: | ---: |
| OpenSSH | 92.644 / 99.015 ms | 1878.221 / 1948.598 ms |
| russh 0.63.1 | 80.050 / 94.246 ms | 1569.817 / 1660.197 ms |

At 300ms RTT the observed median difference is 308.404ms (16.4%). This is
one 25-sample run; p99 is the maximum sample, not a reliable tail estimate.

| Client retained connections | Private memory | Per connection × 200 | RSS / PSS |
| --- | ---: | ---: | ---: |
| 200 OpenSSH processes | 318052 KiB total | 1590.26 KiB × 200 = 310.60 MiB | 1822548 / 321790 KiB |
| russh in one process | 11460 KiB added over baseline | 57.30 KiB × 200 = 11.19 MiB added | 3992 KiB baseline; 15900 KiB retained RSS |

The exact retained russh run was baseline RSS3992 KiB, retained RSS15900 KiB,
RSS delta11908 KiB. Private-memory delta11460 KiB excludes that process's base
runtime, key and libraries. OpenSSH private total includes each client's own
base process; summed RSS repeats shared libraries, so it is a conservative
upper bound rather than exclusive memory. Neither row includes the control
plane, facts, terminal state, kernel buffers or server-side daemon memory.
The default eight-host bootstrap bound also prevents 200 OpenSSH installation
children; 200 connections models later interactive SSH sessions (D4/D170).

| Isolated GNU release executable | Bytes |
| --- | ---: |
| Tokio/stdin baseline | 487280 |
| russh authentication probe | 2578408 |
| Added isolated probe size | 2091128 |

The product adds no SSH client dependency for OpenSSH. The isolated size delta
is not a whole-product musl increment: final LTO sharing, existing dependencies
and the interactive feature set would change it. Both production musl binaries
remain subject to target-specific measured baselines and the unchanged
262144-byte growth allowance; the baseline update is recorded on #87.
The now-reachable production bootstrap builds are 16520048 bytes x86_64 and
13881064 bytes aarch64, with no PT_INTERP (continuation-runtime-fast.log).
These include the full existing product rather than this isolated probe.
OpenSSH is an external system requirement, so its installed binary and
libraries are not included in the product executable size.

## Trust and future interactive sessions

OpenSSH preserves the server's config, known_hosts and existing SSH agent in
place. The adapter forces strict host-key checking, disables updates/TOFU/DNS
admission, forwarding and persistent control sockets. Unknown/changed keys
fail; independent keyscan output is explicitly an unauthenticated fingerprint
observation, never a trust-store write. Effective hostname/port are obtained
with bounded `ssh -G`; proxy configurations do not produce misleading direct
fingerprints. Such configurations are refused until every hop has strict
trust enforcement. Pasted keys/passwords use scoped helpers and private pipes.

russh provides a server-key callback and a known_hosts helper. The measured
probe refuses unknown/changed keys and certificates. The helper's source lacks
OpenSSH wildcard/negation and @cert-authority/@revoked parity; production
migration would require a reviewed trust policy, config/proxy handling and
in-place authentication-agent integration. Authentication success is not enough
to justify changing those semantics.

The client channel APIs provide PTY requests, exec/shell, window change,
stdin/output flow control and exit notifications. Those are suitable primitives
for D4's later SSH fallback, but this probe does not prove interactive latency,
reconnect, cancellation or fidelity. OpenSSH can provide that fallback through
child stdin/stdout too; its per-process cost matters at 200 retained sessions.

russh is Apache-2.0. The locked graph has 178 packages including this AGPL
research package; license metadata permits compatible MIT/Apache/BSD/ISC/
Unicode alternatives. The isolated graph also passes the repository
`cargo deny` advisory, ban, license and source policies, with no license
exception; its raw receipt was removed under D262.
No product dependency was added.
The chosen research crypto feature is ring: the SSH protocol implementation is
Rust, but ring includes native crypto/assembly. This is not a claim that the
entire transitive implementation is pure Rust.

Primary references: [russh client handler](https://docs.rs/russh/0.63.1/russh/client/trait.Handler.html),
[versioned crate sources](https://docs.rs/crate/russh/0.63.1/source/), and
[upstream project](https://github.com/Eugeny/russh). License/source checks use
the exact locked registry source and `cargo metadata --offline`, recorded in
the raw metadata receipt, removed under D262.

## Reproduce

Build the isolated baseline and probe with
`cargo build --locked --release --manifest-path research/ssh-client/probe/Cargo.toml`,
setting CARGO_TARGET_DIR under the job's HOME cache, then run
`systemd-run --user --scope -p CPUWeight=10000 python3 research/ssh-client/measure.py --candidate <release/infraternal-ssh-research>`.
The harness defaults to25 samples/profile and200 retained connections. It
requires local sshd, ssh-agent, ssh-add, openssl and OpenSSH; it binds no public
port and does not contact o1/o2 or any other host.

Recommendation to the owner: keep system OpenSSH for bootstrap because it
preserves existing identity/configuration and reviewed strict trust behavior,
and eight concurrent installation children bound its memory cost. Revisit
russh for 200 interactive sessions: its measured private-memory increment is
about 28 times smaller, with lower authentication latency, but production
trust/configuration parity and interactive behavior still need proof. The
owner decides the foundational engine; no engine change is made by this job.
