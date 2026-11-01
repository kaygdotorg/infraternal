<!-- Describes the metadata-driven infraternal CLI contract and generated skills. -->
# Command line interface

The CLI command tree, help text, and generated skills are adapters over the
registered action definitions (D16, D202). A plugin compiled out of a binary
has no registered command path. Each action supplies its concise description,
usage guidance, ordered steps, input and output JSON Schemas, examples, and
safety notes.

## Human and JSON output

Every command prints the same shape for people: the answer in one plain
sentence first, then short aligned blocks, then `Why` (failures only) and
`Next` (only a follow-up that is true for this state, at most three). Tables
show a header only from two rows, size each column to its widest value, and
wrap only the last column. Width comes from the terminal, then `$COLUMNS`,
then 80, and never exceeds 100. Colour and the state mark (`●` `○` `!` `✕`)
appear only on a terminal; colour is off with `NO_COLOR`. Failures go to
standard error.

Every command, including hidden internal ones, accepts `--json`. JSON is one
compact line per result on standard output, also for failures and usage
errors, so a stream of results can be read line by line:

```json
{"schema_version":1,"command":"remove-host","ok":false,"state":"refused",
 "message":"infraternal remove-host needs --server and <HOST>.",
 "next":["infraternal remove-host --help"],"next_step":"infraternal remove-host --help",
 "error":{"code":"usage","argument":"--server","detail":"..."},"data":{}}
```

Fields are only ever added within `schema_version` 1; removing or renaming one
bumps the version. `ok` is true exactly when the exit code is 0. `error` is
present exactly when `ok` is false: `code` is stable, `argument` names the
argument at fault and never its value. `next_step` repeats the first entry of
`next`. `data` is shaped by the action's output schema. States are `ready`,
`running`, `restarting`, `stopped`, `pending`, `unavailable`, `refused`, `failed` and
`unknown`. A test walks the whole command tree and fails when a command lacks
`--json` or prints anything that is not this envelope.

## Command shape

Bare `infraternal` is the same overview as `infraternal status`, plus one line
pointing to `--help` (a machine with nothing installed is told how to join or
to run a server). A group typed alone, such as `infraternal mesh`, lists its
commands. `status` exits 5 when an installed service is not running.
A service in an automatic restart loop reports `restarting`, with
"Restarting repeatedly" in its component row, its last observed exit status
or signal (or an explicit unavailable value), and a `journalctl` next step for
its system or user manager. Recent repeated starts are treated as unstable
for ten seconds using the manager's monotonic start timestamp; wall-clock
changes cannot shorten that window. Historical restart counts on a stable
process do not change its Running state. Repeated starts without a comparable
monotonic timestamp remain Unknown. Queries use raw properties available to
older systemd clients, without requiring a timestamp-format option.

Status reads local state only. Each unit has independent observations and a
query deadline; concurrent queries keep a stalled unit or manager from hiding
another unit's state. A failed query remains Unknown, with a scoped diagnostic
next step; it does not by itself prove the service is down. Retained server
data without a readable service unit is Stopped, exits 5, and asks the operator
to restore the service. Masking, disabling or removing a unit cannot create a
Running headline without evidence of a running service.

Exit codes (D303): 0 done, 1 failed, 2 wrong command line, 3 not allowed,
4 not found, 5 off or unreachable, 6 partly done, 130 interrupted by Ctrl-C
(terminated by SIGINT).

A command that is not built yet is hidden: it is absent from `--help`, from
`infraternal skill` and from the written skill files, and typing it is an
unknown command (D299). It appears again when it works.

Only `infraternal server init` creates a persistent server service. It prints
the installation plan with `--dry-run`. Applying setup asks for confirmation
on a terminal; non-interactive use must pass `--yes`. The top-level help also
lists `server init` as the first server-setup command. The legacy
`infraternal server install` path remains hidden from help and only prints
migration guidance; it does not create or change a service.

`--data` always selects the server data directory when supplied. Without it,
server commands that read or create server data use the `--data` path recorded
by an installed system service, including its effective drop-ins. If no system
service records a path, they use `./data`. A setup-token command that cannot
read its selected directory prints one line with the matching `sudo` command.

## Generated skills

`infraternal skill` lists the public, working actions registered in this build.
`infraternal skill <command...>` prints one Markdown skill containing front
matter, usage, ordered steps, inputs, the full output JSON Schema, examples,
and safety notes for AI agents. `infraternal skill --write DIR` writes one
`infraternal-<command-path>.md` file per visible action. `--json` wraps the
list, Markdown skill, or written filenames in the same versioned result
envelope. Hidden internal actions are not listed or written.

## Hosted plugin actions

The production Mesh and host-facts descriptors register in the same action
registry as node lifecycle commands. For example, `infraternal mesh node rename
--help` and `infraternal skill host facts read` use the plugin's own descriptions
and instructions. Skills include the original wire schema references and exact
permission alternatives; destructive actions retain required dry-run guidance.
The `mesh` Cargo feature remains an alias for `plugin-mesh`.

`infraternal sign-in <server>` starts a device approval, prints its browser
link and short code, and waits for a fresh passkey approval. It stores the
resulting server credential in the user's private config directory; the
polling token and API key are never printed. Terminal QR output is a measured
follow-up. The stored credential is not yet used by hosted CLI actions, which
remain hidden until the authenticated device-session transport is implemented.

The authenticated CLI device-session transport is not implemented yet, so
hosted actions that need it are hidden placeholders (see above); they cannot
bypass authorization or change a temporary local collector.
Their real server handlers, durable switches and subscription topics continue to
run through the generic plugin host. `infraternal server init` remains the only
CLI service-creation path.

With no default features the CLI keeps the action contracts and registry, while
Tokio and SQLx in the plugin API are enabled only by `socket-host`. Node-side
plugin descriptors and bounded action routing do not need those dependencies.

## Saved-session automation (D314, #251)

On Linux builds with `plugin-agent`, run these commands from a saved shell in
this machine's app terminal, using the same operating-system account:

```sh
infraternal sessions [local]
infraternal sessions new local --name build
infraternal sessions new local --name check -- /bin/sh -c 'make check'
infraternal sessions send local:build 'make check'
infraternal sessions read local:build --last 20
infraternal sessions close local:build
```

The machine's exact hostname also works. A target accepts its saved name or
stable UUID after the colon. Lists retain stable UUID order across pages.
Names contain 1–64 ASCII letters, digits, dots,
dashes or underscores, excluding `.` and `..`. Names survive daemon restarts
in private state; names of live sessions must be unique on that account.
`send` adds no newline and reports only bytes acknowledged written to the PTY.
It never retries an uncertain input write. `new -- …` executes literal program
arguments, preserving empty arguments and metacharacters, through a bounded
private pipe; it does not construct shell source. Without a program it starts
the account's normal login shell. `close` reports that closure was requested;
it does not claim that the process has exited. It requests shutdown of the saved
shell even when a job owns the foreground terminal. An older shim without the
close capability returns an upgrade/recreate instruction. CLI-created sessions retain output
for the existing one-shot exit deadline (up to ten minutes), including programs
that exit before a viewer connects. Other interactive launches keep their existing
ownership and retention policy.

`read --last N` accepts 1–10000 and returns up to N trailing lines from the
latest 4096 retained bytes. It reports `truncated` when earlier bytes/lines
were omitted or the bounded JSON reply required trimming. `snapshot` identifies
screen recovery when exact retained bytes are unavailable. Output is text with
lossy UTF-8 replacement; JSON escapes control characters and human output
prints terminal control characters visibly. Reading never resizes the PTY.

Every operation accepts `--json` and uses the existing version-1 envelope.
The CLI combines bounded local pages into one complete list; if a later page
fails, exit 6 preserves the rows already received. Listings reflect live discovery
rather than a snapshot across concurrent creation/closure.
Data fields are `sessions` (rows with `id`, `name`, `machine`), `session` for
creation, `bytes_sent` for send, `text`/`truncated`/`snapshot` for read, and
`session`/`close_requested` for close. Errors retain D303 exit codes and name
the next step. A mistyped session name can suggest a nearby available name.
Generated skills are available with `infraternal skill sessions <verb>`.
`--state` selects an existing private infraternal-agent state folder for local
installations using a non-default path.

The daemon checks kernel peer credentials and live saved-shell ancestry before
running an operation. An environment marker or a matching UID alone grants no
session automation authority. Requests across machine or account boundaries
are refused. Remote device credentials and approvals, wait/watch/rename/MCP,
the compatible command subset, and canvas commands are later slices. There is
no CLI attach operation; interactive use belongs in the app.
