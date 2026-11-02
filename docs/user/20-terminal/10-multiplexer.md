<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Former slugs: multiplexer -->
<!-- Role: the page behind the ? in the "switch to the Infraternal Multiplexer" notice (D315, #251). Published at /docs/terminal/multiplexer/. Reading aids used here: GitHub-style alerts, [!WHY] reasoning blocks, [!FACTS] quick facts (the "?" preview), a quote, and [^n] citations (docs-extras.ts). -->
# The Infraternal Multiplexer

Infraternal keeps every terminal alive on its host, so you rarely need tmux or Zellij on top of it.

## What it does for you

> [!FACTS]
> Every terminal is a session that keeps running on its host. Close the tab, lose the connection or upgrade Infraternal: the shell goes on.

Every terminal you open in Infraternal is a **session**. A session keeps your shell running on the host, whatever happens to the screen you are looking at. That is the job of a multiplexer, so Infraternal has one built in.

- **Sessions survive disconnects.** Close the tab, lose the connection, lock the phone or put the laptop to sleep. The shell and everything in it keep going on the host. Open the app again and the window shows the screen where you left it, then catches up with the live output.
- **Sessions survive upgrades.** Each session has its own small process, separate from the Infraternal agent (the program that runs on each host). The agent can upgrade and restart without ending your shells.
- **The same session on every device.** Start a build on the laptop, look at it from the phone.
- **Windows, not prefix keys.** You arrange sessions as windows on the canvas. There is no prefix key to learn, and no status bar drawn inside the terminal.

![Three terminals on the canvas, each its own window: a backup on the home server, a photo index on the media server, and updates on a Raspberry Pi.](figure:sessions-windows "Every session is a window on the canvas, so you move between them with the canvas, not with a prefix key.")

## Why you may want to switch

If your shell starts tmux[^tmux] or Zellij[^zellij] by itself (a line in `~/.zshrc`, `~/.bashrc` or your fish config), every Infraternal terminal ends up as a multiplexer inside a session. That means two scrollbacks, two sets of keys and two things that can hold on to a screen.

> [!WHY] Why most people do not need the second layer
> Sessions already keep your shell alive. What tmux or Zellij add on top is mostly what a session gives you without them: a shell that outlives the screen, and the same shell from another device.
>
> Running both costs you something every day (two scrollbacks, two sets of keys) and buys you little, so Infraternal offers to remove the second layer. It never does so on its own.

### The question Infraternal asks

When Infraternal sees tmux or Zellij start automatically in a new terminal, it asks once for that host:

> tmux started automatically. Would you like to switch to the Infraternal Multiplexer instead?

![The question over a terminal on the home server, with a tick, a cross and a question mark. The tick is pressed, the exact change is shown, it is confirmed, and Restore puts the original line back.](figure:multiplexer-switch+clip "Answering the question: the tick shows the exact change first, and Restore puts the original line back.")

| Button | What it does |
|---|---|
| ✓ | Switches. Infraternal shows you the exact change first and edits the file only after you confirm. |
| ✗ | Keeps tmux or Zellij as it is, and does not ask again on this host. |
| ? | Opens this page. |

The question appears once per host. You can turn it off for everyone, or for one host, in Settings under Multiplexer.

## How switching works

> [!FACTS]
> One line changes: a condition in front of the command that starts tmux or Zellij. You confirm it first, and you can restore the original line.

Every Infraternal session sets the variable `INFRATERNAL_SESSION`. Switching adds one condition in front of the line that starts the multiplexer, so that line runs only when the variable is empty:

```sh
# before
exec tmux new-session -s main
# after
[ -n "$INFRATERNAL_SESSION" ] || exec tmux new-session -s main
```

Only Infraternal terminals change. An SSH login from another terminal, a console, or any shell without the variable still starts tmux or Zellij as before. You can also start either one by hand in any terminal, whenever you like.

> [!WHY] Why a condition and not a rewrite
> The line stays where you wrote it, with the same command, so everything else about your startup keeps working. Only the terminals that Infraternal started skip it. If you ever stop using Infraternal, the line still does what it did before.

### What stays untouched

> [!IMPORTANT] Nothing changes without your say
> Infraternal never changes how your shell starts without asking: no wrappers, no hidden environment tricks. It changes the one line you confirmed, and it keeps the file's permissions and line endings.

### Which files it can edit

Infraternal edits these startup files in your home directory, when the multiplexer is started by a line of its own (optionally with `exec`):

- bash and sh: `.bashrc`, `.profile`, `.bash_profile`, `.bash_login`
- zsh: `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`
- fish: `config.fish` and `conf.d/*.fish`

> [!NOTE] More involved startup files
> If your startup is more involved (several commands on one line, redirections, files that load other files), Infraternal does not guess. The ✓ button then copies the condition, and you place it yourself.

## Undoing a switch

After a switch, the notice offers **Restore** with the file's name. It puts the original line back, and only that line, so other edits you made to the file since are kept.

> [!NOTE] When a restore is refused
> If that line is no longer there exactly as Infraternal wrote it, or appears more than once, nothing is changed and you are told. The switch itself is refused the same way when the file changed after Infraternal looked at it.

> [!TIP]
> To undo by hand, delete `[ -n "$INFRATERNAL_SESSION" ] || ` from the front of the line.

## Sessions from the command line

The app is where you use sessions. The `infraternal` command is for automation: scripts, and AI agents such as Claude or Codex that need to start a build, watch it and read its output. It never attaches you to a session.

### The sessions commands

| Command | What it does |
|---|---|
| `infraternal sessions [<machine>]` | List sessions |
| `infraternal sessions new <machine> --name <n> [-- cmd]` | Start a session |
| `infraternal sessions send <machine>:<session> '<text>'` | Type into a session |
| `infraternal sessions read <machine>:<session> --last N` | Read recent output |
| `infraternal sessions wait … --until-idle <d>` or `--match <re>` | Wait for a quiet moment or for text |
| `infraternal sessions watch …` | Follow output, read-only |
| `infraternal sessions rename …` and `close …` | Rename or end a session |
| `infraternal sessions mcp` | Offer sessions to AI agents as an MCP server[^mcp] |

Every command takes `--json`. To put a session on your screen, use `infraternal canvas open <machine>:<session>`.

### The tmux commands it understands

AI agents already know tmux commands, so the same sessions answer to a small subset of them: `new-session`, `send-keys`, `capture-pane`, `list-sessions`, `kill-session` and `split-window`. Anything else fails with a clear "not supported", and attaching is never part of it.

### What needs approval

> [!IMPORTANT] Your own sessions only
> Within your own sessions on the same host and account there are no prompts. Anything that reaches another host or account is refused unless an access rule allows it and it is approved.

### What works today

> [!WARNING] Under review
> A command appears in `infraternal --help` only once it works. The startup question and its ✓ ✗ ? buttons are live. The `sessions` and `canvas` commands are being built in the order of the list above, so this page describes where they are going. Run `infraternal --help` on your machine to see what is available today.

[^tmux]: [tmux, a terminal multiplexer](https://github.com/tmux/tmux/wiki): the multiplexer many people start from their shell's startup file.
[^zellij]: [Zellij, a terminal workspace](https://zellij.dev/): the other multiplexer the question looks for.
[^mcp]: [Model Context Protocol](https://modelcontextprotocol.io/): how an AI agent is offered tools and data.

---

Behind this page: D44 and D223 (the docs are served by each instance), D314 (the `sessions` commands and the tmux subset), D315 (the startup question and its buttons). Tracked on issue #251.
