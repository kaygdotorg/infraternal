<!-- Documents root-only in-memory server replacement, cold compatibility and rollback [168][184][217][224], #154. -->
# Updating a server

Updates and rollbacks use `infraternal server restart`. A root system server can
retain an unlocked CA across an eligible replacement. A non-root server still
replaces its executable, but always restarts cold and reports `CA locked` in its
reply. Stop/start, crash and reboot also start locked until an administrator
unlocks the CA with a passkey. Public trust still permits host verification and
reconnection while locked.

Warm handoff requires the versioned infraternal ELF capability note in the target,
a root-owned executable without group/world write or set-ID, and root ownership
without group/world write on **every** parent directory. Symlinks and `..` path
components are refused. The receiver opens the target once and execs that same
descriptor, preserving the validated inode across a pathname replacement.
The checked image descriptor is kept above the standard descriptors so a
closed stdin cannot cause redirection to overwrite it. Cold stdin stays open
through exec, including when opening `/dev/null` reused fd 0.
The note proves protocol compatibility; it does not authenticate a release.
D184/D224 release-signature verification is deliberately deferred at the opened-fd
hook. The development signing policy uses `release/allowed_signers`, SSHSIG
namespace `infraternal-release`; verify the staged release externally until that
hook is implemented.

Both releases must implement handoff for a warm replacement. The first transition
from a release without restart support is cold. Rolling back to an executable
without the capability note passes `/dev/null` as stdin and starts cold-locked.
An already locked source remains locked: restart never creates an issuer or
bypasses administrator authorization.

Use the running service account for these commands (root for a system service).
Keep the previous executable and configuration until the new release passes its
checks. Never place signing keys in files, command arguments or environment
variables.

1. Verify the release signature according to the release procedure. Stage a
   regular executable on the same filesystem, retaining the old inode for
   rollback. For example, keep the old image at
   `/var/lib/infraternal/bin/infraternal.previous` and stage the candidate at
   `/var/lib/infraternal/bin/infraternal.next`. For warm deployment, root must own
   both the candidate and every parent directory, with no group/world write.
   A user-mode install may use its service-owned private directory, but replaces
   cold. Do not modify an executable inode in place.
2. Ask the running server to exec the candidate, using its existing data root:

   ```sh
   /var/lib/infraternal/bin/infraternal.previous server \
     --data /var/lib/infraternal restart \
     --binary /var/lib/infraternal/bin/infraternal.next
   ```

   The acknowledgement reports a warm handoff or a cold replacement. It confirms
   intent; the service retains its PID, startup flags and configuration.
3. Poll `/healthz` through the normal HTTPS/reverse-proxy route with a deployment
   deadline, for example 30 seconds. Check the release version, remote host
   reconnection and a resumed terminal. Check `/remote/ca/status` from an
   administrator session: an intended warm deployment must report `locked: false`.
   Health alone does not establish a successful CA handoff.
4. If the successor is serving but checks fail, use its restart command with
   `--binary /var/lib/infraternal/bin/infraternal.previous`. The same eligibility
   checks govern rollback. If it has crashed, recover with the retained image and
   unlock the cold CA with an administrator passkey. Never extract a seed from
   disk or include one in a restart request.
5. After checks pass, update the unit's `ExecStart` path to the accepted release
   and run `systemctl daemon-reload`, so later cold boots use it. Retain the
   previous release for the rollback window.

For systemd, generated installations with the remote feature include:

```ini
[Service]
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
```

`systemctl reload infraternal-server` reopens the current install path and uses
the same handoff policy. If the running inode was renamed over and appears as
`(deleted)`, reload reopens the configured invocation path. Use `--binary` to
select a separately staged path. `systemctl restart` is a cold stop/start. Keep
`KillMode=process` so session shims survive replacement.

An invalid restart target, failed reply or failed reload request is logged and
leaves the live server running. Requests record kernel peer PID/UID, target and
outcome without private transfer data. SIGHUP has no socket peer credentials;
it is identified as a signal request. Early reloads are queued across exec and
startup. If the restart endpoint cannot start, the server logs that failure and
continues serving without it.

The old process queues one frame of at most 2090 bytes into an anonymous socket
and closes the writer. Runtime shutdown is bounded to four seconds; owned child
cleanup escalates from SIGTERM to SIGKILL after two seconds and bounds reaping
at three seconds. The same opened executable descriptor is then execed. Exec
removes the old address space before import; no signer or courier remains awaiting
an acknowledgement.

The successor disables dumpability as its first main action, checks the anonymous
channel's preserved PID and UID, and consumes/detaches stdin before loading cold
configuration. Installation requires the exact retained issuer. Invalid imports
stay locked; stdin becomes `/dev/null`, or is closed if descriptor cleanup fails.
Child launch paths explicitly detach stdin, including the embedded infraternal
agent. The short-lived SSH prompt helper retains the existing proc-based peer
authentication policy; it never receives the CA transfer descriptor.

Dedicated seed, transport and receive mappings require `mlock` and
`MADV_DONTDUMP`; protection failure makes handoff cold. On a 4 KiB page host,
serialization peaks at two pages (8 KiB) per server, independently of host/PTY
count; receiving uses one page. Full mappings are cleared before release.
OpenSSL still owns the persistent signing key and briefly returns an allocator
copy during export, which is immediately zeroized. Kernel socket buffers carry
the bounded transfer frame and cannot be zeroized or excluded with userspace
mapping advice. These protections do not remove those residual copies.

A failed exec ends the old service; its supervisor may start the configured image
cold. A successful exec with an invalid handoff also serves cold-locked. Treat
either outcome according to the administrator CA status and deployment checks.
