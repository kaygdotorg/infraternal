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

## Commands

`infraternal --help` and `infraternal <command> --help` are the authority for
flags and wording. This is the map:

| Command | For |
|---------|-----|
| `status` | what runs on this machine; exits 5 when an installed service is down |
| `skill` | the generated instructions for AI agents (below) |
| `sign-in <server>` | authorise this device on a server with a passkey |
| `hosts list`, `hosts add`, `hosts remove`, `hosts forget` | manage the hosts a server admits |
| `remove-host <HOST>` | remove a host (needs `--server`) |
| `sessions` | saved-session automation on this machine (below) |
| `up <server>` | join this Linux machine or Mac to a server |
| `uninstall` | review and remove the local install, with `--system` for system installs in scripts |
| `agent join`, `agent run` | enrol this machine and keep the infraternal agent connected |
| `mesh status`, `mesh peers`, `mesh up`, `mesh down` | this machine's Mesh node |
| `publish`, `unpublish` | expose a local service through the node proxy |
| `server` and `server init`, `setup-token`, `channel`, `release`, `restart`, `mesh` | run and manage the server |

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

Without a server credential, `status` reads local state. With `--server` or one
unambiguous stored server credential, it reads that server's status instead.
Local checks give each unit an independent observation and query deadline; a
stalled unit or manager cannot hide another unit's state. A failed local query
remains Unknown, with a scoped diagnostic next step; it does not by itself
prove the service is down. Retained server data without a readable service
unit is Stopped, exits 5, and asks the operator to restore the service.
Masking, disabling or removing a unit cannot create a Running headline without
evidence of a running service.

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

`--relay-port` enables the server node's IPv4 UDP relay socket and requires
`--remote-listen`. `infraternal server init --system --relay-port` writes the
persistent host-firewall rule for that socket. A direct `infraternal server
run` binds the socket but does not change firewall state.

`--data` always selects the server data directory when supplied. Without it,
server commands that read or create server data use the `--data` path recorded
by an installed system service, including its effective drop-ins. If no system
service records a path, they use `./data`. A setup-token command that cannot
read its selected directory prints one line with the matching `sudo` command.

`server init` never depends on the directory it runs in (D395). When the
unit it would write already exists, init keeps that unit's `--web-root` (or
its absence), so a re-run on an unchanged install plans the same unit and
changes nothing, even with `--force`. `--system` also reuses the data folder
an installed system server records under another name, as before. The
server's data folder is
`$XDG_STATE_HOME/infraternal` (else `~/.local/state/infraternal`) per user on
Linux, `/var/lib/infraternal` system-wide on Linux (D229), and
`~/Library/Application Support/infraternal` or
`/Library/Application Support/infraternal` on macOS. When the Linux system
install shares its base with an infraternal agent, the default is
`/var/lib/infraternal/server`, mode 0700 and owned by the server account.
The shared base keeps its traversal permissions, and the infraternal agent
keeps its paths and the existing system command link. An empty or relative
`XDG_STATE_HOME` is ignored, as the XDG specification says. Without
`--web-root`, a fresh install uses the `web/` folder beside the `infraternal`
binary (the release bundle layout) when it exists, and otherwise leaves the
flag out. A relative `--data` or `--web-root` is refused, and the error names
the absolute path to pass instead. `--system` needs root, except with
`--dry-run`; without `--system`, init installs a per-user service, for root
too. Root runs what a system install writes (the server and firewall
units and the command link all name the running binary, which init does not
copy), so a real `--system` install, or root's own per-user one, refuses a
binary another account could replace: the file and every folder above it must
be owned by root and not writable by group or others (a sticky folder such as
`/tmp` counts as protected). The web folder the unit serves (`--web-root`, or
the `web/` beside the binary) is held to the same rule, and so is everything
inside it: every folder and file must be owned by root and not writable by
group or others, and it may contain no links, because whoever can change a
served file can run their own script in a signed-in administrator's page.
Move the release folder somewhere only root can change, such as
`/opt/infraternal`, and run init from there; `--dry-run` prints a warning
instead (#146). A real install creates a missing data
folder with mode 0700.
`--dry-run` prints the resolved `Data folder` and `Web folder` as absolute
paths. The rules live in `crates/infraternal/src/install_paths.rs`.

An existing install moves to the standard folder too (D395, amended
2026-11-15). When the unit records a different `--data` and you do not pass
`--data`, `server init` moves the server data (database with its WAL and
SHM files, identity, SSH trust and the mesh key) and rewrites the associated
`ExecStart` paths in the unit and its drop-ins. Pass
`--data <current folder>` to keep a folder where it is. `--dry-run` prints the
move first: the two folders, the method, and the unit files it rewrites.
The move stops the service and copies its data into a private staging folder.
It syncs the copy, verifies file contents and metadata, publishes the checked
firewall policy, and then switches the unit and its drop-ins. The effective
`ExecStart` is switched last. The old path remains available until the new
server answers its health check and the main process reported by systemd confirms
the open database's path, device and inode over the private control socket.
A fresh challenge ties the HTTP response to that same process.
Across filesystems, or after an unconfirmed startup, init keeps a dated,
read-only backup and prints its location. Otherwise,
init reopens the configured destination and renews the database and HTTP proof
just before removing the original. An inconclusive check leaves the original
available, possibly at the recorded backup path.

After confirmation, init loads recovery hooks on the server unit, stops the
original service, records the request, and asks systemd to start the server.
The systemd job continues if the CLI exits. The next start, including after
reboot, can process a recorded request even if the CLI never submitted its
start. The pre-start hook prepares and selects the destination. The post-start
hook verifies it before systemd reports a successful start. A failure surfaces
as a failed start and leaves the request available for retry. The private journal
records the data paths and identities, staging and backup locations, and
complete unit set. If the moved server
may have accepted writes, recovery keeps both trees and retries the selected
destination. On a combined host that stored server data directly in the
shared base, the same systemd job copies only the server entries into the
private child. The journal tracks each original server entry so recovery can
resume retirement after a partial cleanup. Reserved install paths and the
host firewall policy files stay in the shared base. Other moves that would
take over a shared base are refused before stopping the service. Init also
refuses a destination with unrelated files or a concurrent configuration change, such as a new listen
port, even with `--force`. Use the existing
service flags for relocation and apply changes separately.

Relocation is a no-op for an install already at its standard folder, such as
a combined system server in `/var/lib/infraternal/server`. Ordinary
`server init` still reconciles the service and firewall. Relocation leaves sockets in `/run`
alone. The server's updater (#211) is meant to call the same move while
the service is stopped; `server restart --binary` keeps the service running
and never moves the folder. On macOS, `server init` does not install a
launchd service yet, so there is no macOS server install to move; the move
itself works there the same way.

## Adding a Mac: user mode and root mode (#146, D203 C2 as amended 2026-11-20)

`infraternal up https://infra.example.org` on a Mac joins in **user mode** by
default. Run it as the person who uses the Mac, without `sudo`:

- It asks for your administrator password once, before the approval code, to
  install a small mesh helper (`kayg.infraternal.mesh-helper`). The helper runs
  only when the infraternal agent asks it for something, then exits. It creates
  the mesh network interface, routes the mesh's addresses to it (it refuses if a
  network the Mac already uses overlaps them), and points `/etc/resolver` at the
  agent for `internal` names. Nothing asks for the password again, after a
  reboot or a new login either.
- The infraternal agent runs as you, from
  `~/Library/LaunchAgents/kayg.infraternal.agent.plist`, with its files in
  `~/Library/Application Support/infraternal` and its log in
  `~/Library/Logs/infraternal/agent.log` (D395). `up` prints the `PATH` line
  to add.
- Only one account per Mac can use user mode, and not beside root mode.
- A Mac that joined with an older build has the same pieces under `org.infraternal.*`
  names. Run `infraternal up` again: it asks for the administrator password once,
  removes the old helper and the old `LaunchAgent`, and installs the new ones.
  The enrollment and the mesh key stay where they are, so the Mac keeps its
  identity. macOS may ask about Local Network access again, because it tracks
  the program by its new identifier (`kayg.infraternal`); click Allow.
  Removal takes both the old and the new pieces.
- To remove it, run
  `infraternal uninstall`
  as the same person. It stops the agent, which drops the mesh interface and
  its routes, removes the helper's resolver file and the helper itself, and
  deletes the files above. It needs no password.

`infraternal up --system https://infra.example.org` keeps **root mode**: a
LaunchDaemon that runs before anyone logs in, for a Mac without a regular
user.

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
registry as node lifecycle commands. A plugin action that has a CLI command
uses the plugin's own description and instructions: `infraternal mesh peers
--help` and `infraternal skill mesh peers` print them. Mesh node management
actions such as `mesh.node.rename`, and host-facts reads, have no API scope
yet, so they are not CLI commands and `infraternal skill` does not list them. Skills include the original wire schema references and exact
permission alternatives; destructive actions retain required dry-run guidance.
The `mesh` Cargo feature remains an alias for `plugin-mesh`.

`infraternal sign-in <server>` starts a device approval, prints its browser
link and short code, and waits for a fresh passkey approval. It stores the
resulting server credential in the user's private config directory; the
polling token and API key are never printed. Terminal QR output is a measured
follow-up. Read-only scopes are requested by default; repeat `--scope <scope>`
to request additional authority, which the approval screen displays before the
passkey tap. The stored credential powers hosted actions through
`Authorization: Bearer`. `--server https://…` selects a stored server
credential when more than one is present.

The hosted key actions are `status`, `hosts list`, `hosts add`, `hosts remove`,
`hosts forget` and `sessions list`. `hosts add` streams each setup step and the captured
remote setup failure detail. `hosts remove <id> --dry-run` shows what would be
removed and changes nothing. `hosts remove <id>` first shows that same dry run, asks
`Type yes to confirm`, and only then removes the host and uninstalls its
infraternal agent (D28). `--yes` skips the question for scripts; `--json` and
pipes need it. The owner can use `hosts forget <id>` as soon as a host loses
access and shows pending cleanup. This drops the list entry, stops pending
cleanup and keeps the audit record. The dry run explains how to clean up any
remaining installation on the host. This command also supports `--dry-run` and `--yes`. Inside its `hosts:write` scope the key needs no further passkey tap
(D333); the tap was the key's approval, and every call is audited. Reads are
counted per key and minute rather than logged one row per call.

Hosted actions without an explicit API scope remain unavailable to the CLI;
they cannot bypass authorization or change a temporary local collector.
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
