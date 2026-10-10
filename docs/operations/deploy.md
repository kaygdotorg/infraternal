<!-- Documents in-memory server replacement and rollback without cold-locking the CA [168][217], #154. -->
# Updating a server

Updates and rollbacks use `infraternal server restart`. Do not stop/start the
service for a deployment: that is a cold start and locks the CA until an
administrator unlocks it with a passkey. A crash, reboot or failed handoff also
starts locked. Existing host verification and reconnection need only public trust.

Both releases must implement the handoff protocol for a warm replacement. The
first deployment from a release without restart support requires a cold transition
and administrator unlock. Rolling back to a release without the import adapter
starts cold-locked; it cannot recover the departed process's signing key.

Use the service account for these commands (root for a system service). Keep the
existing binary and configuration until the new release passes its health checks.
Never place signing keys in files, command arguments or environment variables.

1. Verify the release signature according to the release procedure, then stage
   the executable beside the old executable, on the same filesystem. Preserve
   the old path for rollback and leave the old inode intact. For example, with
   the current executable at `/var/lib/infraternal/bin/infraternal.previous` and
   a verified candidate at `/var/lib/infraternal/bin/infraternal.next`, make the
   candidate executable and owned by the service account. Keep the directory
   private and prevent other users from changing either file. The executable and
   every parent directory must be owned by the service account or root and
   must not permit other writes. Group-writable directories are accepted only
   below an owned private ancestor inaccessible to other users; executable
   files must never be group-writable. Symlinks, set-ID executables and parent-directory (`..`) path components are
   refused; stage a regular executable at its final path.
2. Ask the running server to exec the candidate, using its existing data root:

   ```sh
   /var/lib/infraternal/bin/infraternal.previous server \
     --data /var/lib/infraternal restart \
     --binary /var/lib/infraternal/bin/infraternal.next
   ```

   The command acknowledgement means replacement was requested. The service PID
   remains the same; startup flags and configuration are retained.
3. Poll `/healthz` through the normal HTTPS/reverse-proxy route until it responds
   successfully, with a deployment deadline (for example 30 seconds). Check
   the release version, remote host reconnection and a resumed terminal. From
   an administrator session, check `/remote/ca/status` for `locked: false` if
   it was unlocked before the update. Health alone does not prove CA handoff.
4. If the new process is serving but the deployment checks fail, use its restart
   command with `--binary /var/lib/infraternal/bin/infraternal.previous` to roll
   back through the same handoff. If the new process has already crashed, there
   is no in-memory signer left: recover service with the retained old executable
   and unlock the CA with an administrator passkey. Do not recover a signing
   seed from disk or attempt to place it in a restart request.
5. After checks pass, update the unit's `ExecStart` path to the accepted release
   and run `systemctl daemon-reload`, so a later cold boot uses that release.
   Keep the previous binary for the rollback window.

A cold-locked server remains cold-locked across handoff; restart never creates an
issuer or bypasses administrator authorization. The inherited handoff is tied to
the same service UID and PID, accepts one bounded frame, and requires the exact
retained issuer. The transfer endpoint is anonymous and inherited as stdin;
ordinary local restart requests carry only an executable pathname.

For systemd, add the following to the service. Builds with the remote feature
include it in generated installations:

```ini
[Service]
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
```

`systemctl reload infraternal-server` execs the current executable through the
same handoff. To switch to a separately staged path, use the restart command with
`--binary`. `systemctl restart` performs stop/start and is a cold start. Keep
`KillMode=process`: session shims must survive the server's replacement.


The old process writes a frame of at most 2,090 bytes into an anonymous socket,
closes the writer, drops its runtime and execs the verified replacement. Exec
removes the old address space before the receiver imports the key, so there is
no old signer awaiting acknowledgement and no surviving courier process. Kernel
peer credentials must match the preserved PID and service UID before any bytes
are read. Import validates the frame and exact retained issuer, clears temporary
buffers, and replaces stdin with `/dev/null` before child processes start. Failed
imports remain locked. Crash dumps and ordinary same-UID descriptor inspection
are disabled for this path.

Keep deployment acknowledgement separate from health confirmation. A failed exec
ends the old service; its supervisor may start the configured executable cold.
A successful exec with an invalid handoff also serves cold-locked. Neither result
should be accepted as a warm deployment merely because `/healthz` responds.
