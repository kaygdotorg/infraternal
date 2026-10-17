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
`running`, `stopped`, `pending`, `unavailable`, `refused`, `failed` and
`unknown`. A test walks the whole command tree and fails when a command lacks
`--json` or prints anything that is not this envelope.

## Command shape

Bare `infraternal` is the same overview as `infraternal status`, plus one line
pointing to `--help` (a machine with nothing installed is told how to join or
to run a server). A group typed alone, such as `infraternal mesh`, lists its
commands. `status` exits 5 when an installed service is not running.

Exit codes (D303): 0 done, 1 failed, 2 wrong command line, 3 not allowed,
4 not found, 5 off or unreachable, 6 partly done, 130 interrupted.

A command that is not built yet is hidden: it is absent from `--help`, from
`infraternal skill` and from the written skill files, and typing it is an
unknown command (D299). It appears again when it works.

Only `infraternal server init` creates a persistent server service. It prints
the installation plan with `--dry-run`. Applying setup asks for confirmation
on a terminal; non-interactive use must pass `--yes`. The legacy
`infraternal server install` path remains hidden from help and only prints
migration guidance; it does not create or change a service.

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

The authenticated CLI device-session transport is not implemented yet, so
hosted actions that need it are hidden placeholders (see above); they cannot
bypass authorization or change a temporary local collector.
Their real server handlers, durable switches and subscription topics continue to
run through the generic plugin host. `infraternal server init` remains the only
CLI service-creation path.

With no default features the CLI keeps the action contracts and registry, while
Tokio and SQLx in the plugin API are enabled only by `socket-host`. Node-side
plugin descriptors and bounded action routing do not need those dependencies.
