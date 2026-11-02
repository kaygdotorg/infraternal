# Shell startup hints [D315, #251]

Every session exports a nonempty `INFRATERNAL_SESSION`. No multiplexer variables,
startup hooks, command wrappers, shell options or startup arguments are changed.
The D241 interception is superseded, including on shell `exec` handoff.

`terminal.startup` is a bounded authenticated core terminal action, using the same
account-owned session and host resolution as attachment. JSON objects only:

- `{"op":"get","host_id":<optional owned remote UUID>}` reads account and host
  hints: `global_enabled`, nullable `host_override`, and effective `enabled`.
- `{"op":"set","global":true,"enabled":<boolean>}` saves the account default.
  With `global:false` (the default), `host_id` selects a host; omission selects
  the local host. `enabled:null` clears a host override. Switches control hints
  only and never edit files. No setting changes the session marker.
- `{"op":"inspect","session":<UUID>}` checks a newly opened, untyped session.
  The node observes the authenticated shim's process tree for at most two seconds,
  including an `exec` that retains the shell PID. It reads executable identities
  and the exported marker, never terminal output. A host's notice is claimed
  atomically only after detection. Typed or older sessions cannot consume it.
  A host whose notice has been shown skips all further process inspection.
- `{"op":"apply"|"undo","session":<UUID>,"proposal":<exact proposal>,
  "confirmed":true}` changes the corresponding user's startup file. The browser
  sends apply only after the shared confirmation. Undo removes only the uniquely
  matching guard, preserving other edits. Missing confirmation is refused.

The actor injects its admitted execution UID; the browser cannot select a UID,
PID, home, shell, file content, or command to execute. A single-use helper drops
to that user before reading startup files. Discovery is read-only and fails open;
the terminal opens independently of the hint request. At most four bounded helper
requests run per host connection. There is no recurring work after inspection.

Recognised startup locations are bash/sh profiles and `.bashrc`, zsh's
`.zshenv/.zprofile/.zshrc/.zlogin` (including `ZDOTDIR` under the user's home), and
fish's config and at most 32 `conf.d/*.fish` files (including `XDG_CONFIG_HOME`
under the home). An isolated `tmux` or `zellij` command, optionally prefixed by
`exec` or an absolute executable path, can be guarded in place. Multiline `if`
bodies work in all three shells. Compound lists, quoting, redirections, arbitrary
sourced files and locations outside the home remain manual: the notice offers a
copyable guard without claiming it can rewrite unknown shell syntax.

An edit revalidates the original invocation and the whole-file SHA-256 fingerprint.
Only owned, single-link regular files without extended attributes are replaced;
symlinks at every path component are refused. Refusing extended attributes avoids
discarding ACLs or security labels. Replacement also refuses attributes inherited by its temporary file, so a
directory default ACL cannot grant new access. It keeps the mode, group and line
ending, uses a temporary file in the open directory, syncs it, verifies the current
path still names the original content/inode, then renames and syncs the directory.
An independent editor can still race the final pathname check and rename; like
other atomic editors, the helper cannot provide a filesystem compare-and-swap.

## What the person sees (owner wording, 2026-11-01, #251)

The notice is one question with three icon buttons, never the word "guard":
"<tmux|Zellij> started automatically. Would you like to switch to the
Infraternal Multiplexer instead?" ✓ switches (the `apply` flow above: shared
confirmation first, then a "Restore <file>" undo), ✗ keeps the other
multiplexer (no write: the host's notice is already claimed), ? opens
`docs/user/20-terminal/10-multiplexer.md` on the docs site (`/docs/terminal/multiplexer/`). When no startup line can be edited,
✓ copies the line instead. Each button has a tooltip and the same accessible
name. The switches stay in Settings under Multiplexer.

## Production browser fixture

The dedicated `real/startup-guard.spec.ts` runs with `D315_NAMESPACE=1` only in a
private user/mount namespace. Map the current UID/GID unchanged (`unshare --user
--map-current-user --mount --keep-caps`); bind a private passwd file over
`/etc/passwd` there, changing only that user's home and login shell to a private
home and the Nix zsh executable. No host account or shared startup file changes.
Set `HOME` to that private home and `D315_TMUX` to the Nix tmux executable. The
test starts the real static binary and built tracer, opens a real PTY whose zsh
startup executes tmux, then checks discovery, cancel, confirm, undo and reload.
It captures 1440×900, 393×852 and 375×667 in ink and paper. The fixture's existing
authenticated teardown retires only its shims, and each tmux socket is unique.
