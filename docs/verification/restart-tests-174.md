<!-- Record of the restart test failure investigation and verification for issue #174. -->
# Restart test investigation (#174)

## Finding

The restart implementation is not the cause of the five failures and two stalls. This was a test-build environment mismatch plus test fixture bugs.

The baseline Cargo test image was built with umask `0002`, which produced mode `0775`. `restart_binary::Opened::open` deliberately rejects `metadata.mode() & 0o6022 != 0`; group-write (`0020`) therefore correctly returned `PermissionDenied`. The tests copied or reused the Cargo test image as a replacement without making it private. Requests that needed the default executable were refused, leaving `Control::requested` waiting for a later valid request. Two tests consequently stalled; five asserted through the refused path and failed.

Two related fixture assumptions were also fixed. The Cargo test image has no `ACFIINFRATERNAL` ELF note, although the rootless and root-owned handoff tests need a marked fixture. They now add the note only to copied images that are inspected but never executed. A half-close in the closed-reply test did not close the client's read side, so the server's reply could still succeed. The test now shuts down the read side before sending its request. The deleted-image test now uses a hard-linked executable fixture, unlinks its running pathname, and writes the replacement at that path; this avoids the intermittent `ETXTBSY` observed while spawning the copied fixture.

The tests now use private per-test directories below `$HOME/.cache/codex-scratch/infraternal/restart-tests`, make executable fixtures mode `0700`, set child stdin explicitly, and bound subprocesses and request waits. Timed-out subprocess process groups are killed. The real-fd child has a 9-second deadline to tolerate the lower-weight plain shell under natural host load; every child deadline is below 10 seconds. The production validator and restart path are unchanged.

## Plain shell and systemd scope context

Measurements in both contexts:

| Property | Plain shell | `systemd-run --user --scope -p CPUWeight=10000` |
| --- | --- | --- |
| UID | 1001 | 1001 |
| stdin | `/dev/null`, not a TTY | `/dev/null`, not a TTY |
| open FDs | `0`–`4` | `0`–`4` |
| effective capabilities | `0000000000000000` | `0000000000000000` |
| blocked signal mask | `0000000000000000` | `0000000000000000` |
| child subreaper | 0 | 0 |
| cgroup | `codex-restart-tests.service` | `run-….scope` |

Among these measured process fields, the cgroup path was the only difference. The host reported 12 online CPUs. No synthetic load was started. `/tmp` was `tmpfs rw,nosuid,nodev` (no `noexec`); `/home` was `ext4 rw`. Test state was on `/home`, not `/tmp`.

The default restart fixture socket path is 88 bytes, below Linux's 108-byte `sun_path` limit. An early matrix run set `INFRATERNAL_TEST_STATE_ROOT=/home/kayg/.cache/codex-scratch/fix-restart-tests/state`, making the restart fixture socket 100 bytes. That override made two unrelated `agent_review` fixtures construct 116-byte socket paths, so the combined run's two integration tests failed before running their checks. The final combined runs used the default state root and passed. This was a matrix configuration error, not a restart failure.

## Individual test matrix

Each baseline test ran alone in a plain shell and in the weighted systemd scope. The baseline harness used a 10-second outer guard: exit 101 means the test failed; exit 137 means the guard killed it after 10 seconds. Fixed durations below are Cargo wall time from the matrix, except where noted. The final combined runs reran every row after the final fixture changes; individual reruns after the last edits cover closed-reply, reload, and real-fd, while unaffected rows use their fixed-matrix individual results.

| Test | Baseline plain | Baseline scope | Fixed plain | Fixed scope |
| --- | --- | --- | --- | --- |
| `closed_reply_and_missing_reload_target_do_not_end_restart_control` | timeout `>10s` | timeout `>10s` | pass, 1.19s | pass, 0.80s |
| `cold_exec_with_closed_stdin_keeps_the_image_pinned_and_maps_null` | fail, 0.92s | fail, 1.04s | pass, 6.88s | pass, 1.08s |
| `default_restart_opens_the_receiver_target_exactly_once` | timeout `>10s` | timeout `>10s` | pass, 4.10s | pass, 1.23s |
| `early_hangup_is_queued_until_control_installs_its_handler` | fail, 2.50s | fail, 3.01s | pass, 8.69s | pass, 0.83s |
| `private_control_endpoint_cannot_be_stolen_or_created_by_a_client` | pass, 0.70s | pass, 0.76s | pass, 9.83s | pass, 0.64s |
| `private_path_prefix_cannot_authorize_a_parent_directory_escape` | pass, 0.46s | pass, 0.76s | pass, 2.53s | pass, 0.64s |
| `real_fd_exec_pins_replacement_and_cold_rollback_uses_null_stdin` | fail, 0.96s | fail, 1.56s | pass, 1.91s test time | pass, 0.72s |
| `reload_reopens_install_path_when_the_running_inode_was_replaced` | pass, 2.72s | pass, 2.17s | pass, 3.31s | pass, 1.15s |
| `replacement_never_exports_to_a_general_purpose_binary` | pass, 0.57s | pass, 0.89s | pass, 9.84s | pass, 1.02s |
| `restart_request_logs_kernel_peer_target_and_cold_outcome` | pass, 0.75s | pass, 0.71s | pass, 3.72s | pass, 1.21s |
| `restart_requests_use_the_servers_binary_and_reject_untrusted_paths` | fail, 5.48s | fail, 5.95s | pass, 4.85s | pass, 0.66s |
| `reviewer_fifo_replacement_is_refused_without_waiting_for_a_writer` | pass, 0.54s | pass, 0.61s | pass, 3.79s | pass, 0.68s |
| `root_owned_marked_target_requires_protected_root_parents` | skipped, 0.42s | skipped, 0.66s | skipped, 1.89s | skipped, 0.92s |
| `rootless_even_marked_replacement_is_cold_and_open_fd_pins_the_inode` | fail, 0.91s | fail, 0.99s | pass, 3.40s | pass, 1.90s |
| `runtime_directory_symlinks_and_public_permissions_are_refused` | pass, 0.45s | pass, 0.64s | pass, 0.98s | pass, 0.64s |
| `runtime_shutdown_never_waits_forever_on_a_blocking_waiter` | pass, 4.65s | pass, 4.90s | pass, 4.83s | pass, 4.73s |

The root-owned row returns immediately for non-root users. The measured UID was 1001 in both contexts, so its protected-root branch was not exercised by this matrix.

The baseline matrix therefore reproduced exactly five failures and two stalls in both contexts. In the first fixed plain matrix, the 10-second outer guard expired before Cargo finished launching the real-fd and reload tests; both were rerun without that outer guard. The current real-fd test completed in 1.91 seconds in the plain shell and 0.72 seconds in the weighted scope.

## Combined command

The final plain-shell combined command was `cargo test -p infraternal restart` with no state-root override: exit 0 in 8.397 seconds, with 18 unit tests and 2 `agent_review` integration tests passing. Unit tests took 4.09 seconds and the integration tests 3.04 seconds. One-minute load average was 28.59 at start and 28.14 at finish.

The same command ran 10 consecutive times on the final code head in `systemd-run --user --scope -p CPUWeight=10000`. Every run passed 18 unit tests and 2 integration tests:

| Run | Wall time | Load average at start | Load average at finish |
| ---: | ---: | --- | --- |
| 1 | 7.688s | 11.11, 24.17, 35.78 | 11.19, 23.97, 35.65 |
| 2 | 8.006s | 11.19, 23.97, 35.65 | 12.99, 23.94, 35.51 |
| 3 | 7.904s | 12.99, 23.94, 35.51 | 13.27, 23.63, 35.29 |
| 4 | 7.702s | 13.27, 23.63, 35.29 | 13.49, 23.50, 35.18 |
| 5 | 7.725s | 13.49, 23.50, 35.18 | 13.82, 23.25, 34.98 |
| 6 | 7.569s | 13.82, 23.25, 34.98 | 13.12, 22.95, 34.82 |
| 7 | 7.439s | 13.12, 22.95, 34.82 | 12.50, 22.49, 34.54 |
| 8 | 7.750s | 12.50, 22.49, 34.54 | 12.22, 22.27, 34.40 |
| 9 | 7.747s | 12.22, 22.27, 34.40 | 11.65, 21.81, 34.13 |
| 10 | 7.725s | 11.65, 21.81, 34.13 | 11.11, 21.53, 33.97 |

The first combined fixed diagnostic used the long state-root override described above: all 18 unit tests passed, then the two unrelated `agent_review` fixtures failed their own 116-byte path check. With the default state root, the final plain combined run and all ten scoped runs passed.

## Full-gate fixture correction

The first full gate with `CARGO_TARGET_DIR` under the required job scratch path reached `agent_review::initial_attach_requires_explicit_credit_before_replay`, whose helper failed before its assertions with `FileNotFoundError: target/ac<PID>` because the worktree had no `target/` directory. `scripts/verify-agent-attach-credit.py` now uses the shared `fixture_state('ac')` helper for a private state path. With the worktree `target/` still absent, the exact integration test passed in the weighted systemd scope in 2.95 seconds. This was an unrelated verification-script path assumption surfaced by keeping build output outside the worktree.

A later full gate exposed the same build-directory assumption in `agent_sessions::detached_shim_is_discovered_and_replays_from_the_last_observed_offset`: it used `../../target/ar<PID>`, whose parent was absent with the external target directory. The exact test reproduced `ENOENT` in 0.01 seconds, then passed in 0.04 seconds after commit `e1bf4208` moved its private state to the user cache and added a `<108`-byte socket-path check. `cargo fmt --all --check` and `cargo clippy --locked -p infraternal --all-targets` also passed after that change.

## Author review

- Production restart code and its strict executable/ownership checks are unchanged.
- No test was removed, ignored, or weakened. Handoff-marked fixtures are private copies used only for inspection; executable test fixtures are mode `0700`.
- Per-test directories are unique and removed by `Drop`. Timed-out child process groups are killed, and each child receives explicit stdin and captured output.
- No dependencies or product performance paths changed. The root-only branch remains unverified on this UID-1001 host and is labeled skipped in the matrix.
