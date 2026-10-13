<!-- Defines D255 shim-first host provisioning and the persistent window setup event contract (#189). -->
# Host provisioning with an early terminal

D255 changes the connection to a session, never its shell. Sign in using the
existing strict SSH adapter. Its read-only check and verified staging share one
duplex command channel; after check/mode/ownership admission the trusted server
sends a bounded public setup script (decimal length, at most 65,536 bytes). This
envelope carries no credential and reuses existing canonical check, failure and
transfer parsers. Automatic authentication may replay only that exact read-only
check, selects its method before testing bridge support, and retains the
selected command channel. Legacy adapters retain buffered commands. Stage the
matching compressed or verified reused payload, then launch a session shim and its shell over that same connection.
The canvas attaches through an SSH channel bridged to that shim. Install and
join continue while the person types. The infraternal agent discovers the same
shim, and the existing terminal actor replaces its SSH transport with the
admitted transport using ordinary reattach and replay. Close SSH only after
that reattachment succeeds. Never adopt a shell started outside a shim.

Preserve the host id, session id, execution uid, writer identities, input
acknowledgments and absolute output offsets through the handover. Inputs whose
acknowledgment was lost are replayed through the shim's existing deduplication;
outputs resume at each viewer's existing cursor. No input queue is discarded
on connection replacement. A failure after terminal publication preserves the
session and reports the failed setup stage. It cannot run fresh-install
rollback over a live user session. Before publication, existing cancellation,
ownership checks, stale setup recovery and durable retirement still apply.

## Host setup events

The host status subscription first returns retained events, then live events.
It belongs to the host and continues after the wizard socket closes. Admission
uses the same current person, host ownership and component lifecycle as normal
terminal access. Revocation and component-off retire the subscription and
prevent further setup actions. The event envelope is additive:

```json
{
  "setup": {
    "host_id": "<uuid>",
    "session_id": "<uuid>",
    "window_id": "<canvas window id>",
    "attempt": 1,
    "sequence": 1,
    "stage": "install",
    "state": "running"
  }
}
```

`stage` is `install`, `join`, `start` or `ready`; `state` is `running`,
`done` or `failed`. A failed event may add a classified `failed_step`
(`connect`, `upload`, `install`, `join`, `start`, `readiness`) and a safe
human `message`. No remote output, command input or credential enters it.
A stage may emit running then done, or done alone. `ready:done` means the
installed transport has reattached the existing session. A retry starts a
new attempt and keeps the existing session. Sequences increase per host;
replay overflow is explicitly reported as resync with current stage states.

The terminal publication event carries `host_id` and `session_id`. The canvas
supplies its window id when subscribing; the server does not invent a layout
id or equate it with the session id. A session can have multiple windows, so
each subscriber receives its own window id with otherwise identical events.
The machine pill consumes these events; no ready toast is required. Mapping:
connect/upload/install failures affect install, join affects join, start
affects start, readiness affects ready.

## Host status adapter

The SSH server component exposes `/v1/bootstrap/setup/ws` with the same exact
Origin and current unlocked-owner cookie admission as the wizard. First send
`{"action":"subscribe","host_id":"<uuid>","window_id":"<canvas id>","after":0}`.
It replays retained events before live delivery. `{"action":"replay","after":N}`
requests replay; overflow sends a host/window-bound `resync:true` followed by
authoritative current stage states. `{"action":"retry","host_id":"<uuid>"}`
retries only that subscription's host with the requesting live capability.
The declared actions are `ssh.setup-watch` and `ssh.setup-retry` (D16).

Subscriptions are bounded by the shared terminal-stream count. Window ids are
bounded presentation coordinates supplied by the canvas; host and session ids
remain authority coordinates. Host ownership and revocation are checked before
each event and retry; component-off ends subscriptions and provisional bridges.
A socket's closure never cancels a published session's background setup.
Retries are serialized per host and share the global eight-worker admission.

The wizard's additive `done.session_id`, when present alongside `host_id`, names
the published shim to attach. It must not open another shell. Older `done`
events without this field keep the original installed-terminal behavior.

## Real-login compatibility (D240, D247)

The early session must use the same host-login launcher and person/account
identity as installed terminals when that work lands. On systemd this is the
per-person long-lived unit with PAMName; elsewhere the host's su/login path.
SSH authenticates delivery and bridging; it is not the session's login owner.
The shim and shell stay inside their original login throughout installation
and handover. The installed infraternal agent adopts the rendezvous and login
identity, never moves an already running shell into a new login. Access
revocation ends that person's login and terminals under the login contract.

## Public payload barrier and warming

The negotiated buffered-command compatibility path waits for `PAYLOAD ready\n`
after the complete verified upload before sending private enrollment stdin.
A host's bounded `head` reader may buffer past the frame boundary; withholding
private bytes until it exits prevents over-read from consuming an invitation.
The duplex shim-first path already has its separate verified upload receipt.
Neither receipt authorizes a host or replaces the existing admission checks.

Configured public payloads warm after the HTTP listener binds. The global
four-entry cache index covers only lookup and eviction; each file identity and
codec has its own single-flight cell. Compression runs outside the index lock.
Component-off cancels warming through the existing activity lifecycle; missing
codecs and non-improving encodings retain the raw transfer path.

The SSH master uses `LogLevel=ERROR` to suppress remote login notices. Its
selective `LogVerbose` override admits only the local `ssh_userauth2` method
receipt, reduced by the existing constant-size recognizer without retaining
raw diagnostic text. SSH control-socket admission remains the sign-in proof.

## Optional session payload (D255, D198)

A release may supply `infraternal-<architecture>-session-musl` beside the full
host payload. It is the same executable built with the session and SSH component
only, using the same shim, rendezvous protocol and terminal dispatcher. These
paths are trusted server configuration; target requests cannot select a payload.
A missing session artifact retains full-payload staging. A present symlink,
directory or inaccessible artifact is refused.

After read-only admission, verified session-payload staging starts the original
shim-owned shell. Once its session is protected and published, the existing
session-preserving setup retry path stages the full host payload over another
command channel on the same authenticated SSH connection. It retires only the
owned installation journal and never truncates the inode backing a live process.
The session, writer cursors, host identity and rendezvous remain unchanged. The
private enrollment input still follows verified full-payload staging. Cancellation,
component-off, ownership checks and failed-setup retry retain their existing
boundaries. D240/D247's per-person login requirement applies to both builds.

The public digest index has four entries (two architectures times two builds),
and the encoding index has eight (two codecs per build). Each encoded entry
retains the existing 64 MiB ceiling. These caches belong to the server; no cache
or compressor is added to a host daemon or a session shim.

## Deferred transfer on the checked connection

Immediate full-payload restaging reuses the bounded compound transfer command.
Its first upload child holds the ordinary directory guard while a separate
fresh errexit child retires only that installation's journal and lease. The
cleanup child inherits the parent's guard; it cannot release the parent's
copy. The next upload recreates the journal through the existing acquisition
path. Session rendezvous and the running executable inode remain untouched.

The same read-only check may supply public rootless encoding support for that
immediate restage. In this case the setup script declares raw, gzip or zstd
and public bytes follow without waiting for a selection round trip. The reader
requires the exact matching `TRANSFER` receipt and `PAYLOAD ready` before
private enrollment input can flow, even when an older caller omitted its
optional acknowledgment flag. Reuse still requires ordinary digest selection;
unknown capabilities, root setup and later retries retain negotiation. No
check-time hint authorizes installation or bypasses ownership, digest, terminal
proof or commit checks.

The session image is built with the internal `session-payload` feature, which
implies SSH and selects its private entrypoints when server/transport/host-facts
components are absent. The same shim option record, defaults and runner remain
shared with the full build. Its argv decoder accepts only the canonical shape
emitted by the session launcher, including readiness and detach suffixes; it
never executes fuzzed or unknown invocation shapes. Operator commands and
inherited-fd startup belong to the installed full image. The cross-build oracle
therefore names that full image when it adopts the original shim. Full and
all-component builds retain the public CLI.

After publication, installed facts and the private terminal canary may run
concurrently. Each independently waits for installed authority and checks owner
and execution UID; both must pass before the commit signal. Failure withholds
commit and finishes only the registered private canary. The person's original
session remains live. Legacy adapters retain sequential proof ordering.
