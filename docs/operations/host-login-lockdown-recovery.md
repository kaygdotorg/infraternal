<!-- Recover the retained host-wide login refusal without bypassing person authority. -->
# Recover host login lockdown

Security-queue overflow currently latches the entire host closed after eighteen
pending people. This behavior is retained pending the owner's policy decision
on #347. Ordinary disk-queue saturation does not trigger it.

The latch is `infraternal-login-locks/host.revoked` under `/run` for a root
infraternal agent, or under the resolved `--state` directory for a rootless
infraternal agent. Use the configured state path, not a guessed environment
value. Do not touch another instance's state.

1. Use an independent administrator shell. Review the revocations in the server
   and the host's logs. Fix the storage/permission problem that prevented cleanup.
   Removing the latch deliberately lifts host-wide denial, so obtain the host
   administrator's authorization before proceeding.
2. Stop **every** infraternal agent using this registry. For a root service use
   `sudo systemctl stop infraternal-agent.service`; for a rootless service use
   `systemctl --user stop infraternal-agent.service`. Confirm it is inactive and
   no manually launched daemon remains. Root daemons share `/run` even when their
   configured state directories differ. A live retry owner can recreate the latch.
3. As the registry's owning account, run the following Python snippet, replacing
   the explicit registry path for a rootless instance. It refuses symbolic links,
   unexpected ownership/modes, nonempty files and multiple hard links. If validation
   fails, stop and investigate; do not use a recursive removal or follow the link.

   ```python
   import os
   import stat

   registry = "/run/infraternal-login-locks"
   fd = os.open(registry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
   try:
       directory = os.fstat(fd)
       if directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) != 0o700:
           raise SystemExit("unsafe login registry; investigate without removing it")
       marker = os.stat("host.revoked", dir_fd=fd, follow_symlinks=False)
       if not (stat.S_ISREG(marker.st_mode)
               and marker.st_uid == os.geteuid()
               and stat.S_IMODE(marker.st_mode) == 0o600
               and marker.st_size == 0 and marker.st_nlink == 1):
           raise SystemExit("unsafe host marker; investigate without removing it")
       os.unlink("host.revoked", dir_fd=fd)
       os.fsync(fd)
   finally:
       os.close(fd)
   ```

4. Start the infraternal agent again. A fresh process starts without positive
   login grants. Missing refusal markers alone never grant access. The trusted
   server must resynchronize current authority before a person can open a login.
   Unconfirmed server cleanup is replayed over a cleanup-only reconnect; it never
   restores normal remote authority or publishes an available host.
5. Explicitly restore only the people the server currently authorizes, using the
   server's add-host/restoration operation. It validates and durably removes that
   person's refusal before granting access. Do not manually remove person markers.
   Verify the intended person can open a login and another revoked person remains
   denied. If lockdown recurs, stop and repair the underlying cause before retrying.

The regression `stopped_host_latch_recovery_requires_validated_removal_and_explicit_restore`
uses a child daemon fixture that exits before maintenance, validates and removes
only the host marker, checks that access remains denied, then restores one person
and verifies another remains denied. Restoration cannot override a live host latch.
