<!-- Field recovery and lifecycle verification for remote infraternal agents, #225. -->
# Recovering a disconnected infraternal agent

A server cannot restart a host process that has no working server link. Restarting
or unlocking the server cannot deliver an update to that process. Use an existing
host administration channel to restart the installed service once; a fleet command
runner can execute the same command on each affected host. Do not reinstall,
re-enroll, remove retained identity, or stop session shims.

For a rootful systemd installation:

```sh
sudo systemctl restart infraternal-agent.service
sudo systemctl is-active infraternal-agent.service
sudo journalctl -u infraternal-agent.service -n 30 --no-pager
```

For a rootless systemd installation, run as the account that installed it:

```sh
systemctl --user restart infraternal-agent.service
systemctl --user is-active infraternal-agent.service
journalctl --user -u infraternal-agent.service -n 30 --no-pager
```

For an unattended rootless restart from a privileged administration session,
select the actual installation account; do not assume the administrator owns it:

```sh
account=INSTALLATION_ACCOUNT
uid=$(id -u "$account")
sudo -u "$account" env XDG_RUNTIME_DIR="/run/user/$uid" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
  systemctl --user restart infraternal-agent.service
```

Both generated service variants retain `KillMode=process`, so restarting the
infraternal agent preserves independent terminal shims. New installations use
`Restart=always`, `RestartSec=2`, and `StartLimitIntervalSec=0`. Existing installed
units are not rewritten by this source change. Their `Restart=on-failure` still
restarts the updated binary after an unexpected server-link return, which now
exits nonzero.

After restarting, confirm the host appears in the server and open a terminal.
Service-active status alone does not prove admission. Retained enrolled host
certificates and public transport trust permit reconnect while the server CA
signer is locked [168]; fresh enrollment and certificate renewal still require
an unlocked signer. Expired identity or revoked host authority requires a separate
administrator action. A generic TLS refusal is not sufficient evidence of
revocation and must not permanently disable retries.

## Verification boundaries

An idle TCP fallback can remain half-open when a server disappears without a
FIN/RST reaching the host. In 9ab4329c, `remote_client.rs:123` awaits authenticated
daemon dispatch, and `crates/plugins/remote/src/remote_tls.rs:70` awaits an idle
read with no keepalive configured by `dial`. The reconnect loop has not returned
in this case: it is still waiting for the old socket. Outgoing fallback sockets
now use kernel keepalive and a bounded Linux unacknowledged-write timeout, so a
lost peer wakes the existing reconnect loop without a daemon heartbeat timer.

The field release 9ab4329c uses `new_current_thread()` in
`crates/infraternal/src/main.rs`. One sleeping thread is consistent with a running
async loop and does not establish that runtime shutdown has started. The old
release directly awaits its server-link loop; it has no `remote_server_path.rs`.
The newer path loop can return on credential and local service failures; the
supervisor now retries those returns and restarts continuously offline attempts
after five minutes. Unexpected top-level returns or panics exit nonzero after
bounded runtime shutdown, allowing the service manager to restart the process.

Process reproduction uses `scripts/verify-agent-reconnect` in private user/network
namespaces, isolated data, a private runtime directory and no session bus. Set
`INFRATERNAL_RECONNECT_STALL_SECONDS` to pause the old server with SIGSTOP while
its kernel listener still accepts TCP, before SIGKILL, no route, and a cold server
replacement. The test prints the infraternal agent thread count at each phase.
The runner defaults to stalled userspace, TCP-only transport, and packet discard.
`INFRATERNAL_RECONNECT_BLACKHOLE=1` discards both directions of the
transport before killing the old server. This prevents its close from reaching
the client; lowering loopback alone can still deliver a local TCP close.
`INFRATERNAL_RECONNECT_TCP_ONLY=1` drops UDP so the fallback is exercised.

Its default disconnected interval is 600 seconds; an override is for functional
iteration only. Compile the same test and browser helpers at the oldest server
revision so the initial fixture database matches that server's schema. Freeze a
copy of the shell runner before a long run. Build-host wall times are not
performance evidence. On the performance VM only,
`INFRATERNAL_RECONNECT_MEASURE=1` prints full-daemon RSS and listener-ready to
terminal admission for the individual trial. Copied fixtures can locate cleanup
scripts and the isolated shell profile with
`INFRATERNAL_REMOTE_FIXTURE_REPOSITORY`; namespace UID/GID overrides select an
existing fixture account. Results and raw receipts are recorded on #225.
