<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Role: the page behind the ? in the "switch to the Infraternal Multiplexer" notice (D315, #251). Published at /docs/multiplexer. -->
# The Infraternal Multiplexer

Every terminal you open in Infraternal is a **session**. A session keeps your
shell alive on the host, whatever happens to the screen you are looking at.
That is what a multiplexer is for, so Infraternal has one built in: the
Infraternal Multiplexer.

## What it does for you

- **Sessions survive disconnects.** Close the tab, lose the connection, lock
  the phone or put the laptop to sleep. The shell and everything running in it
  keep going on the host. Open the app again and the window shows the screen
  where you left it, then catches up with the live output.
- **Sessions survive upgrades.** Each session has its own small process,
  separate from the Infraternal agent (the program that runs on each host). The
  agent can upgrade and restart without ending your shells.
- **The same session on every device.** Start a build on the laptop, look at it
  from the phone.
- **Windows, not prefix keys.** You arrange sessions as windows on the canvas.
  There is no prefix key to learn, and no status bar drawn inside the terminal.

## Why you may want to switch

If your shell starts tmux or Zellij by itself (a line in `~/.zshrc`,
`~/.bashrc` or your fish config), every Infraternal terminal ends up as a
multiplexer inside a session: two scrollbacks, two sets of keys and two things
that can hold on to a screen. Sessions already keep your shell alive, so most
people do not need the second layer.

When Infraternal sees tmux or Zellij start automatically in a new terminal, it
asks once for that host:

> tmux started automatically. Would you like to switch to the Infraternal
> Multiplexer instead?

| Button | What it does |
|---|---|
| ✓ | Switches. Infraternal shows you the exact change first and edits the file only after you confirm. |
| ✗ | Keeps tmux or Zellij as it is, and does not ask again on this host. |
| ? | Opens this page. |

The question appears once per host. You can turn it off for everyone or for one
host in Settings, under Multiplexer.

## How switching works

Every Infraternal session sets the variable `INFRATERNAL_SESSION`. Switching
adds one condition in front of the line that starts the multiplexer, so it
runs only when that variable is empty:

```sh
# before
exec tmux new-session -s main
# after
[ -n "$INFRATERNAL_SESSION" ] || exec tmux new-session -s main
```

- **Only Infraternal terminals change.** An SSH login from another terminal, a
  console, or any shell without the variable still starts tmux or Zellij as
  before.
- **Nothing else is touched.** Infraternal never changes how your shell starts
  without asking: no wrappers, no hidden environment tricks. It changes the one
  line you confirmed and keeps the file's permissions and line endings.
- **Starting it by hand still works.** Type `tmux` or `zellij` in any terminal
  whenever you like.
- **Files it can edit:** the startup files of bash and sh (`.bashrc`,
  `.profile`, `.bash_profile`, `.bash_login`), zsh (`.zshenv`, `.zprofile`, `.zshrc`,
  `.zlogin`) and fish (`config.fish` and `conf.d/*.fish`) in your home
  directory, when the multiplexer is started by a line of its own, optionally
  with `exec`. If your startup is more involved (several commands on one
  line, redirections, files that load other files), Infraternal does not guess.
  The ✓ button copies the condition for you to place yourself.

## Undo

After a switch, the notice offers **Restore** with the file's name. It puts the
original line back, and only that line, so other edits you made to the file
since are kept. If that line is no longer there exactly as Infraternal wrote
it, or appears more than once, nothing is changed and you are told. The switch
itself is refused the same way when the file changed after Infraternal looked
at it.

To undo by hand, delete `[ -n "$INFRATERNAL_SESSION" ] || ` from the front of
the line.

## Sessions from the command line and for AI tools

The app is where you use sessions. The `infraternal` command is for
automation: scripts and AI agents such as Claude or Codex that need to start a
build, watch it and read its output. It never attaches you to a session.

The `sessions` commands (D314):

| Command | Does |
|---|---|
| `infraternal sessions [<machine>]` | List sessions |
| `infraternal sessions new <machine> --name <n> [-- cmd]` | Start a session |
| `infraternal sessions send <machine>:<session> '<text>'` | Type into a session |
| `infraternal sessions read <machine>:<session> --last N` | Read recent output |
| `infraternal sessions wait … --until-idle <d>` or `--match <re>` | Wait for a quiet moment or for text |
| `infraternal sessions watch …` | Follow output, read-only |
| `infraternal sessions rename …` and `close …` | Rename or end a session |
| `infraternal sessions mcp` | Offer sessions to AI tools as an MCP server |

Every command takes `--json`. To put a session on your screen, use
`infraternal canvas open <machine>:<session>`.

**The tmux-compatible subset.** AI tools already know tmux commands, so the
same sessions answer to a small subset of them: `new-session`, `send-keys`,
`capture-pane`, `list-sessions`, `kill-session` and `split-window`. Anything
else fails with a clear "not supported", and attaching is never part of it.

**Boundaries.** Within your own sessions on the same host and account there are
no prompts. Anything that reaches another host or account is refused unless an
access rule allows it and it is approved.

> **Status.** A command appears in `infraternal --help` only once it works. The
> startup question and ✓ ✗ ? buttons above are live. The `sessions` and
> `canvas` commands are being built in the order listed on issue #251; this page
> describes where they are going, and `infraternal --help` on your machine is
> the source of truth for what is available today.
