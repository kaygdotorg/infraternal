# Build slots

The build VMs install `scripts/build-host/build-slot` as
`~/infraternal-ops/build-slot` under the `claude` account. Ordinary callers
keep their existing commands. The numbered locks and ordinary FIFO under
`/tmp/infraternal-build-slots` are shared with older callers. Old holders finish
normally and become eligible for lease management on their next launch.

- `slots` next to the script is the ordinary capacity. Compute01 uses 6 and
  dev-02 uses 3. Setting it to 0 pauses admission while current holders finish.
- `reserved-nightly` contains 1 on compute01 to enable a seventh, dedicated
  slot. `build-slot --reserved nightly COMMAND …` uses the dedicated FIFO and
  lock. Ordinary jobs never take that slot. Dev-02 has no nightly reserve.
- `build-slot --status` shows the locks, queues and disk floors.
- `build-slot --reap-dry-run` lists currently eligible tickets without
  signalling or changing them. Waiters and the five-minute user timer run
  the same reaper. An actual reap is recorded in
  `/tmp/infraternal-build-slots/reaper.log` and on the reaper's stderr.

Set `BUILD_SLOT_JOB` and `BB_THREAD_ID` in the VM command environment for
attribution. Each slot ticket records the supervisor PID, command PID,
process group, boot ID, and start time. The VM supervisor renews its lease
every five minutes. A detached BB launcher may also set
`BUILD_SLOT_OWNER_LEASE` to a unique absolute path on the VM. In that mode
the control host must touch the file before launch and at least every five
minutes while the thread is active. Once the thread ends, stop renewing.
A signal requires both ten minutes without renewal and an hour with no CPU
progress by any member of the ticket's process group. A failed thread status
lookup is not proof that the job ended. The VM does not query BB directly.

For rollback, stop the user reaper timer and drain the new holders before
restoring `~/infraternal-ops/build-slot.bak-j1365`. On compute01, also remove
the `reserved-nightly` configuration and restore the old nightly coordinator
before its timer fires. Leave the numbered lock inodes in place during both
installation and rollback.
