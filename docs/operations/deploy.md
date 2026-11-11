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
Delegate=yes
```

`systemctl reload infraternal-server` reopens the current install path and uses
the same handoff policy. If the running inode was renamed over and appears as
`(deleted)`, reload reopens the configured invocation path. Use `--binary` to
select a separately staged path. `systemctl restart` is a cold stop/start. Keep
`KillMode=process` so session shims survive replacement. `Delegate=yes` lets the
infraternal agent run each Traefik process in its own cgroup under the unit, so
stopping the proxy also stops anything it forked (#281, D336). Without it the
proxy falls back to process-level reaping, and `infraternal mesh status` says so.

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

A replacement now requires the hardened signed MANIFEST, signature and VERSION
beside its executable. The immutable verified image is probed before shutdown;
late exec refusal recovers the retained current image with an independent CA
handoff. See [safe replacement](replacement.md) for admission, recovery and
platform qualifications. A successful exec with an invalid handoff still serves
cold-locked; check administrator CA status after every replacement.

## Rolling back across a database migration

A release refuses to start on a database that a newer release migrated: its
migrator does not know the newer versions and stops with `VersionMissing(N)`.
A rollback within the deploy itself is safe: the production deploy script
copies `/var/lib/infraternal` after stopping the server and, when the 20 s
health check fails, restores that copy together with the previous binary.

A deliberate rewind later (`ALLOW_REWIND=1` to an older SHA after a bug shows
up in production) is different. Its copy is taken after the newer migrations
ran, so the old binary fails its health check and the script puts the new
binary back. Restoring an older backup by hand loses every change since it was
taken. When the newer migrations are additive (new columns or tables only, as
`0026_mesh_node_name_source` and `0027_mesh_node_name_claim` of #236 are), set
their bookkeeping rows aside instead. With the server stopped and a fresh copy
of `infraternal.sqlite` taken, before the rewind:

```sql
BEGIN;
CREATE TABLE rewind_migrations AS SELECT * FROM _sqlx_migrations WHERE version > 25;
CREATE TABLE rewind_mesh_names AS
    SELECT id,name,(SELECT revision FROM mesh_state WHERE singleton=1) AS revision
    FROM mesh_nodes;
DELETE FROM _sqlx_migrations WHERE version > 25;
COMMIT;
```

Replace `25` with the newest version the older release ships. The older release
ignores the extra columns. New rows take their defaults (for 0026, a name
counts as chosen by a person), but renaming an existing row changes only `name`:
its newer automatic provenance stays untouched. Keep `rewind_mesh_names` for
the whole rewind. Before rolling forward again, with the server stopped, mark
names changed since that snapshot, or explicitly renamed in the audit log during
the rewind, as chosen by a person and clear their old automatic claim. The audit
check also preserves a person choosing the same spelling or changing back to it.
Unchanged automatic names retain their provenance, so ordinary record and
hostname updates still work. Then put the migration rows back so
the migrator does not try to add the columns a second time:

```sql
BEGIN;
UPDATE mesh_nodes SET name_source='hand',name_claim=NULL
WHERE id IN (
    SELECT previous.id FROM rewind_mesh_names AS previous
    JOIN mesh_nodes AS current ON current.id=previous.id
    WHERE previous.name<>current.name
    UNION
    SELECT CAST(resource AS INTEGER) FROM mesh_audit
    WHERE action='mesh.node.rename'
        AND revision>(SELECT revision FROM rewind_mesh_names LIMIT 1)
);
DROP TABLE rewind_mesh_names;
INSERT INTO _sqlx_migrations SELECT * FROM rewind_migrations;
DROP TABLE rewind_migrations;
COMMIT;
```

A migration that rewrites or drops data cannot be rewound this way; its pull
request must say so and name the backup to restore.

## Restoring an older Mesh authority

Each server process creates a fresh Mesh authority UUID. Before publishing a
snapshot, it commits that UUID to `mesh_state`; if the write fails, it sends no
snapshot. After restoring any database backup, start the server normally. Its
new process UUID makes enrolled nodes fence the previous peer set before they
apply the restored snapshot, even when the backup was taken after the epoch
column was added.

A database restore also restores the Mesh membership from the time of that
backup. It can therefore re-authorize a node that was removed afterwards. The
new authority epoch retires peers left on enrolled nodes, but it cannot infer
removals that are absent from the restored database. Before allowing infraternal
agents to reconnect, compare the restored Mesh inventory with removals made
since the backup and remove those nodes again. Keep agent connectivity blocked
until that reconciliation is complete. For nodes whose card says `needs an update` (their infraternal agent predates epoch support),
do not assume the old local peer set was replaced; upgrade them to epoch support
or keep their mesh traffic blocked until their local Mesh state is reset and
they are re-enrolled.

Nodes keep their last-known rules while the server is unreachable (D166). When a
restarted server reconnects, nodes briefly reapply the full snapshot under the
new authority. No manual SQL reset is needed.

Migration `0029_remote_host_hostname` (#236) adds the retained hostname column
and replaces existing UUID-shaped Mesh placeholders with audited unnamed
labels. A deliberate rewind across it restores the pre-migration database
backup; do not remove its bookkeeping row and run the older binary against the
rewritten names. The deploy script's automatic health-check rollback already
restores the database copy it took before migration.
