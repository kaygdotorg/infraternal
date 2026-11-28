# Nightly browser suite operations (D373, #443)

The nightly browser suite runs on `infraternal-dev-02-std`, the dev-02 build
VM. The dev-02 host operator owns the systemd installation, run storage and
routine service actions. The infraternal owner reviews the pinned source
revision and decides when to install or update it. A job prepares the change
and its evidence; it does not install the timer.

## Schedule and accounts

`infraternal-browser-suite.timer` starts
`infraternal-browser-suite.service` daily. The installer's timer is 05:00
Asia/Kolkata with up to 15 minutes of randomized delay. Since 2026-11-20 the
owner runs dev-02 with a host-local drop-in
(`/etc/systemd/system/infraternal-browser-suite.timer.d/schedule.conf`) that
moves it to 05:30 Asia/Kolkata with up to 5 minutes of delay, so the report is
ready for the morning report. The scheduled service ends browser work at 07:45 IST. The installer does not write that drop-in, so a reinstall keeps it and a
new host needs it added by hand. Do not start gates, builds or load tests on
dev-02 in that window. The service takes two build slots through
`/home/claude/infraternal-ops/build-slot`, one for each Playwright shard.

The `infraternal-browser` system account owns the mode-0700 checkout and raw
runs under `/var/lib/infraternal-browser/`. It has no Forgejo token. The root
service helper validates and copies its output to private staging owned by
`infraternal-fuzz`; only that account runs the root-owned reporter and uses
the Forgejo token. After reporting, the helper copies checked run data to the
operator-readable directory. The reporter writes `merged-report.json` with a
same-directory temporary file, `fsync`, and rename. The helper publishes the
whole run directory with a same-parent rename after syncing its files and
directories. Operators therefore see either no new run or a complete report
and evidence tree.

## Logs, reports and retention

- Unit output and timeout or queue messages: `sudo journalctl -u infraternal-browser-suite.service`.
  The last run's unit state is available with `sudo systemctl status infraternal-browser-suite.service`.
- Private raw run data: `/var/lib/infraternal-browser/runs/<run>/`, including
  `suite.log`, `results.jsonl`, `meta.json`, and `evidence/`. Read it as root;
  the browser account home is mode 0700.
- Operator-readable report and checked evidence:
  `/var/lib/infraternal-browser-pub/<run>/merged-report.json`, alongside the
  copied raw results, log and evidence. The publication tree is root-owned
  (directory mode 0750, files 0640); inspect it with `sudo`. The helper keeps
  the newest seven complete runs.
- Reporter staging: `/var/lib/infraternal-fuzz/browser-staging/`. It is private
  to the token account and remains available for `--report-only` recovery.
- Per-spec failures and timeout or missing-test summaries are filed on the
  Forgejo issues described in `docs/PROCESS.md`.

`merged-report.json` gives each planned test a state and lists missing tests
under `not_run`. A spec is marked passing only when every test in its plan
finished with an expected or flaky outcome. A shard that never starts is
represented from the durable assignment manifest, so its assigned spec files
are named in the report and roll-up note.

## Operate or stop

Inspect the timer and next firing time with:

```sh
sudo systemctl list-timers --all infraternal-browser-suite.timer
sudo systemctl status infraternal-browser-suite.timer
```

Start a manual run with `sudo systemctl start infraternal-browser-suite.service`.
To disable scheduled runs across reboots and abort a currently running one:

```sh
sudo systemctl disable --now infraternal-browser-suite.timer
sudo systemctl stop infraternal-browser-suite.service
```

Re-enable scheduled runs with `sudo systemctl enable --now infraternal-browser-suite.timer`.

The 07:45 IST deadline includes the build-slot queue, checkout, build, and
browser cases. If the deadline arrives during the browser run, the service
cancels the running workload, releases the slots, and stages the streamed
results. The merged report and the issue roll-up say “stopped at deadline.”
The root-owned `/var/lib/infraternal-browser-pub/last-deadline.json` records
which phase reached the cutoff, including a queue or checkout cutoff before
the runner writes a manifest. Publication can continue after 07:45.
The deadline path exits 124.

The helper can be run directly without `--deadline-ist` for an operator-run
suite with the previous separate queue and suite budgets.

If the Forgejo token or login needs repair, rerun only the reviewed reporter
against staged results:

```sh
sudo /usr/local/libexec/infraternal-browser-suite-service --report-only
```

This operation takes no build slot and runs no suite. The report is
deduplicated, and the already published run directory is left unchanged.

## Install or update

Install only on dev-02, after `install-nightly-fuzz` has created the token
account. Use a reviewed full commit SHA. The installer checks the host and
token prerequisite, repairs the system account and publication directory in place,
installs the reviewed helper and reporter copies, verifies the systemd units,
and enables the timer. Repeating the command is safe.

```sh
d=$(mktemp -d) && git clone -q https://git.kayg.org/kayg/infraternal.git "$d/src" \
  && git -C "$d/src" checkout -q --detach <40-hex SHA> \
  && sudo python3 -I "$d/src/scripts/install-nightly-browser-suite" --ref <40-hex SHA>; rm -rf "$d"
```

Pass `--forgejo-login <account>` on the first install to write the root-owned
login file. The installer is intentionally not run by the job that changes
it; the operator installs the reviewed commit after review.
