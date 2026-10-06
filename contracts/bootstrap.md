# Contract: bootstrap, enrollment and upgrades

Status: draft for #10. Implements DECISIONS 9, 17, 18, 21 and 22.

## 1. Who runs SSH

The server never connects to a host (DECISIONS 9). Bootstrap SSH runs in an
infraternal agent that can reach the target: the embedded agent for the
server's own network, or a remote agent that acts as the jump host for its
network. The plugin action is `hosts.agent.install`. The server tells the
agent what to do and holds the state. The agent does the SSH work.

## 2. Steps

Each step emits an event (`hosts.bootstrap.step`). The UI shows the events as
a live timeline. A failed step has a code, a sentence in plain language and,
if one exists, a fix action.

| # | step | details |
|---|------|---------|
| 1 | connect | SSH with the auth for the host (DECISIONS 22): key, cert, password, network identity (NetBird or Tailscale), or a relayed mesh login URL. Host key: trust on first use, shown to the user. A later change of the host key blocks the step. |
| 2 | probe | Read-only. `uname -sm`, `/etc/os-release`, init system, `id -u`, `sudo -n true`, the engine sockets (`/run/docker.sock`, `/run/podman/podman.sock`, `$XDG_RUNTIME_DIR/{docker,podman}.sock`), `systemd --user` and linger, NixOS, SELinux or AppArmor, free space and `noexec` on the candidate directories. The result is a `ProbeReport`. |
| 3 | propose | The UI shows the proposal: "sudo available, docker and kayg podman found → rootful agent". The user confirms with one tap (S1 grill Q3; the auto-install toggle comes later). |
| 4 | upload | The agent streams the static binary for the host arch to a temporary file over SFTP or `cat`. It checks SHA-256 and the release signature on the host before it uses the file. |
| 5 | install | The binary goes into slot A: `/var/lib/infraternal/bin/{a,b}` (rootful) or `~/.local/share/infraternal/bin/{a,b}` (rootless). A `current` symlink points to the slot in use. Then the service: a systemd unit with `KillMode=process`, an openrc, runit or s6 service, or a fallback (`@reboot` cron plus a supervisor loop). On NixOS: we print a module snippet and do not write to `/etc`. |
| 6 | enroll | The server makes a join token: single use, valid for 15 min, bound to the host id and the mode. The token goes to the new agent through the SSH session (stdin, never argv). The agent makes an Ed25519 key pair on the host, sends a CSR and the token, and receives a client certificate from the server CA. The private key never leaves the host. |
| 7 | connect back | The agent dials the server (QUIC, with TCP/TLS as fallback, contracts/wire.md) with mTLS. The server marks the host `online`. |
| 8 | canary | The server opens a canary session, restarts the agent service and checks that the shim survived (contracts/shim.md §2). If not, the install fails and shows the init system's output. |
| 9 | inventory | The first plugin inventory (sessions, and in later slices metrics and engines). Done. |

The SSH connection closes after step 8. All later work uses the agent's
connection.

## 3. Rootful, rootless and promotion (DECISIONS 18)

- One agent per host. Rootful when `sudo -n` works or the SSH user is root.
  Otherwise rootless, as the SSH user.
- A rootful agent manages every context on the host: root docker or podman,
  and each user's rootless engines through that user's runtime sockets.
- **Promotion.** When a later probe finds root access on a host with a
  rootless agent, the UI offers "upgrade to a rootful agent". The steps:
  install the rootful agent, then let it adopt the existing shims (root passes
  the `SO_PEERCRED` check) and the contexts, then remove the user agent and
  its unit. Open sessions survive.

## 4. Lockstep upgrades (DECISIONS 17)

When an agent connects, its `Hello` carries its version. If the version is not
the server's version, the server starts the **upgrade handshake**. This
handshake is frozen forever, so an agent from any old version can upgrade:

```
server → agent  UpgradeOffer { version, arch, size, sha256, signature }
agent  → server UpgradeAccept | UpgradeDecline { reason }
server → agent  binary bytes (chunked, resumable by offset)
agent:          write to the inactive slot, fsync, check SHA-256 and the signature,
                rename the symlink `next`, ask the service manager to restart
new agent:      must send CheckIn within 30 s
                otherwise the supervisor wrapper flips `current` back and restarts the old slot
agent  → server UpgradeResult { ok | rolled_back, logs_tail }
```

- Signature: release binaries are signed with Ed25519. The public key is
  embedded in the binary. Dev builds use a separate dev key, and agents from
  release builds refuse it.
- Downgrade: only if the server sends `UpgradeOffer` with `downgrade=true`
  and a valid signature (DECISIONS 17).
- Failures (wrong arch, `noexec`, disk full, SELinux denial, crash at start)
  roll back and report an `UpgradeResult` with the reason. An agent that
  fails to upgrade keeps working in a restricted read-only mode. It gets a
  new offer on its next connection.

## 5. Uninstall

The action `hosts.agent.uninstall` (destructive, so it needs a dry run or a
tap): stop the service, remove the units, the slots and the state directory,
and revoke the certificate. Open sessions are listed in the dry run before
they are killed.
