<!-- Describes the metadata-driven infraternal CLI contract and generated skills. -->
# Command line interface

The CLI command tree, help text, and generated skills are adapters over the
registered action definitions (D16, D202). A plugin compiled out of a binary
has no registered command path. Each action supplies its concise description,
usage guidance, ordered steps, input and output JSON Schemas, examples, and
safety notes.

## Human and JSON output

Commands print organised human output by default. Results use titled sections,
aligned fields or tables, plain-language states, technical details beneath
failure summaries, and a short next step when one is useful. Terminal colour is
enabled only when output is a TTY and `NO_COLOR` is absent.

Every public command accepts `--json`. JSON uses a stable versioned envelope:

```json
{
  "schema_version": 1,
  "command": "status",
  "state": "stopped",
  "message": "No infraternal server service is running on this node.",
  "next_step": "Run `infraternal server init` to create a server on this node.",
  "data": {
    "role": "node",
    "components": [{"name": "server", "state": "Stopped"}]
  }
}
```

`next_step` and `details` are omitted when they do not apply. `data` is shaped
by the selected action's output schema. State values are `ready`, `running`,
`stopped`, `unavailable`, `failed`, and `unknown`. A command's short `message`
is intended for people; `details` carries technical failure context.

## Command shape

`infraternal status` reports the observed node role and registered component
states. `infraternal up` and component `up`, `down`, and `status` commands are
present where their plugins are enabled; handlers that are not built yet say
so plainly. `infraternal server features` follows the same rule for
runtime-switchable server capabilities (D198, D201).

Only `infraternal server init` creates a persistent server service. It prints
the installation plan with `--dry-run`. Applying setup asks for confirmation
on a terminal; non-interactive use must pass `--yes`. The legacy
`infraternal server install` path remains hidden from help and only prints
migration guidance; it does not create or change a service.

## Generated skills

`infraternal skill` lists visible actions registered in this build.
`infraternal skill <command...>` prints one Markdown skill containing front
matter, usage, ordered steps, inputs, the full output JSON Schema, examples,
and safety notes for AI agents. `infraternal skill --write DIR` writes one
`infraternal-<command-path>.md` file per visible action. `--json` wraps the
list, Markdown skill, or written filenames in the same versioned result
envelope. Hidden internal actions are not listed or written.
