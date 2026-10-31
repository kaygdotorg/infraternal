<!-- Role: local daemon/session-helper contract for native desktop capture [D12,D198,D203,D208]. -->
# Desktop helper v1

This additive contract is local to the logged-in user. It does not alter the
frozen server protocol. The desktop plugin owns the helper and its native
companion; disabling it stops capture, restores window geometry, removes its
indicator and socket, and joins its workers. No server is created [D201].

## Transport and bounds

Use `desktop.sock` in an explicitly supplied user runtime directory. The helper
refuses symlink directories, foreign ownership or any group/other permissions.
The socket is 0600; verify the connected peer's effective UID with the operating
system before reading any byte. One connection controls the helper at a time.
Never unlink an existing endpoint to take over a live helper. The caller
provides the path because launchd and XDG runtime directories differ.

Each message is `length:u32be | version:u8=1 | kind:u8 | payload`.
Length counts version, kind and payload. Reject lengths below 2 or above
4 MiB before allocation; all non-video messages additionally fit 64 KiB.
Unknown versions/kinds, malformed JSON, invalid dimensions and nonfinite
coordinates are errors. EOF halfway through a message terminates the session.
Solicited control requests share one three-second send/reply deadline, including
silence before the first reply byte. Unsolicited idle video has no silence timer;
partial frames retain their deadline. Blocked output ends capture instead of queuing.
Frame payloads are `capture_ns:u64be | keyframe:u8 | H.264 Annex-B bytes`.
SPS/PPS precede each IDR, making saved `.h264` streams directly decodable.
Monotonic timestamps mark the owned-pixel capture request in the native host clock, before capture/copy/encoding. Stream notices are scheduling hints; they do not timestamp these subsequently captured pixels.

| Kind | Direction | Payload |
| --- | --- | --- |
| 1 | daemon → helper | List: `{}` |
| 2 | daemon → helper | Start: target (`window` ID + PID, or `screen` display ID), output pixel width/height, canvas width/height and backing scale |
| 3 | daemon → helper | Resize: output pixel width/height, canvas width/height and backing scale |
| 4 | daemon → helper | Input: mouse move/button, scroll, physical macOS keycode with modifiers, or printable Unicode `text` scalar |
| 5 | daemon → helper | Stop: `{}` |
| 6 | daemon → helper | Status: `{}` |
| 7 | daemon → helper | Keyframe: `{}`; request a fresh IDR only for an existing active capture |
| 8 | daemon → helper | ReleaseInput: `{}`; release held remote input without stopping capture, including during local-input pause |
| 10 | daemon → helper | Control: `{active:bool}`; server lease starts/stops the existing Mac indicator and clears held input |
| 9 | daemon → helper | Congested: `{}`; bounded source-generated network pressure feedback, lowers bitrate without lowering capture rate |
| 65 | helper → daemon | Window inventory JSON |
| 66 | helper → daemon | Geometry JSON: original/actual point frame, output pixel size, content rectangle, follow/letterbox reason |
| 67 | helper → daemon | Input result JSON: accepted or local-input pause |
| 68 | helper → daemon | Status/stop JSON; Status includes read-only `input:{pause_remaining_ms,control_visible}` |
| 69 | helper → daemon | Fixed public error JSON |
| 70 | helper → daemon | Encoded frame (binary) |

Scroll deltas `dx` and `dy` are signed 32-bit integers, matching the public
wire and native event API. Coordinates and modifier bits retain their bounds.
The desktop binary input envelope (`0x43`) adds subtype 4 with one `u32le`
Unicode scalar; invalid scalars, surrogates and C0/C1 controls are rejected before
native side effects. The helper receives `{type:"text",scalar:...}` and posts
the complete UTF-16 sequence as one key-down/up pair. Printable text follows
the viewer's layout; modified shortcuts and navigation use physical keycodes.
The browser adapter tracks each physical key until its matching release,
including a release after the modifier changes. Composition/IME is deferred.

Window identity is session-scoped `(owner_pid,window_id)`; validate both at
start. Inventory is a Core Graphics snapshot joined to NSRunningApplication:
optional bundle ID, app name and title, layer, point frame, on-screen flag.
Displays are separate whole-screen entries. Permission state is separate from
missing optional titles. Optional AX meaning can be added without replacing
identity. Do not persist titles or document paths in logs.

## Capture, geometry and control

ScreenCaptureKit =11.0.0 is behind the capture trait [D204]. A selected-window
stream includes overlapping windows owned by that PID; no other PID is allowed
in its filter [D208 A4]. Whole-screen capture intentionally includes all apps.
Use owned BGRA captures and VideoToolbox H.264, real-time, no frame reordering,
bounded in-flight frames and drop pacing. Once changes settle, send a sharp
forced IDR [D200 V2]. Encode at requested output dimensions.

AX uses points. Desired source pixels are canvas size × backing scale; divide
by the source display’s actual backing scale before setting AX size. Save original point position/size
once, restore on stop and disconnect unless the desktop owns its geometry. Verify actual size after setting it;
refusal or local input in the last 60 seconds means letterbox, with an explicit
content rectangle. Follow once local input becomes idle [D208 A2]. Input coordinates use
output pixels and map through that rectangle; bands accept no clicks.

Managed desktops are detected without a setting [D290]. Before a geometry write,
inspect process executable names for a known tiling manager; never inspect its
arguments, configuration or control socket. Independently, one own-window AX
size notification that differs from our requested size within two monotonic
seconds permanently yields that window to the desktop. Move notifications also
refresh its actual frame. The state lasts for the session, including stop and
disconnect: no further native resize or original-geometry restoration is allowed.
A refused identical size is not retried by the reconciliation timer. A different
canvas size still resizes an unmanaged window. The capture rectangle follows the
real window and its picture fits the canvas with its aspect preserved.

Window Geometry/Status JSON adds `managed:boolean`, `resize_requests:integer`
(cumulative native following requests) and reason `managed`. These diagnostics
are additive; existing readers can ignore them. The signed native regression
checks a managing desktop for 30 seconds across three canvas sizes, with zero
native resize requests and zero source frame-size changes. Run it under the Mac
hardware lock with an owned document; it never changes the window manager.

Bring the selected app forward before accepted remote input. Local physical
mouse/keyboard activity pauses injection for 2 seconds; synthetic remote events
are tagged so they never reset that clock. Show “Controlled from infraternal”
in a small nonactivating panel while control is active. A status item alone is
not sufficient: the system can omit it when the menu bar is full. The private
Status reads the same local-input clock and indicator without acquiring control
or injecting input. Its `input.pause_remaining_ms` is clamped to 0–2000;
`desktop.session.clock` forwards this helper reply. The private
Control acknowledgement adds `control_visible`; acquisition fails unless the
indicator is visible before injection. Screen Recording and Accessibility
must be granted by the person using the Mac; refusal produces a fixed error.

The native companions are private control and encoding children with inherited
stdio, never a second public socket. The pinned wrapper supplies safe owned
BGRA images through SCScreenshotManager; stream callbacks supply change notices.
IOSurface IDs could not be looked up across the private child boundary on the
measured Mac, and framework byte views require unsafe Rust. Owned images avoid
both hazards at a measured copy/capture cost (#146). The private pixel packet
(kind 101) is bounded to 16 MiB pixels plus 1024 bytes of metadata; the public
socket remains bounded to 4 MiB. One owned image is in flight, and at most one
encoded image waits for output. A dropped encoded frame forces the next
transmitted frame to be an IDR, so its references never depend on a dropped frame.
A successful native encoder callback marked `frameDropped` completes its input
without a sample. It must not retire capture. The surface path retains its latest
surface without turning a raw motion drop into decoder reference repair. A
requested IDR or sharp refresh that is dropped retries at the next source-rate
opportunity, using the existing one-shot timer even without further damage.
Sharp refresh retries retain their larger bitrate budget. Ordinary dropped
motion inputs wait for fresh damage or the scheduled settled refresh; they never
cause a forced-IDR loop. The owned-pixel reply makes at most one forced-keyframe
retry of the same captured pixels and timestamp, then refuses repeated drops.
Callback errors, missing unflagged samples, invalid access units and a genuine
completion timeout remain terminal failures. No wire frame is sent for a drop.

Control runs independently of capture/encoding. After 250 ms of identical
owned pixels, a forced IDR receives a larger intra-frame bitrate budget.

The Rust code keeps `forbid(unsafe_code)`; audited platform calls reside in the
small native macOS companions. Bands infer their color from a bounded grid of opaque app-filtered pixels; macOS does not expose another app's NSWindow background
property. A patterned document can make this estimate differ from its actual
background. Whole-screen bands remain black. Native input maps through the
same fitted content rectangle and rejects band coordinates and gaps between owned windows. Pointer delivery additionally requires the topmost on-screen window at the mapped point to belong to the selected PID; occlusion rejects the request. Keyboard events target that PID. Geometry reports the actual source display backing scale.

## Decoder parameter sets (#146, D204/D266)

The native H.264 encoder disables frame reordering. Its progressive one-reference
SPS is rewritten once per distinct parameter set to announce zero reordered
frames and one decoded-picture buffer; unsupported syntax is refused. The
bounded eight-entry cache resets when the encoder session stops. SPS/PPS and
IDR order are retained, and picture NAL bytes are unchanged.

Each keyframe carries the cached restricted SPS followed by a
standard single-message user_data_unregistered SEI (type 5): the 16-byte ASCII
identifier `infraternal-sps1` followed by the exact original SPS NAL (5–1024
bytes), then normal RBSP trailing bits and emulation prevention. The server
strips this metadata before delivery. Existing frame tags, lengths and video
flags are unchanged. Unknown SEI remains opaque; malformed recognized metadata
or metadata without an adjacent SPS is refused.

`desktop.session.parameters` accepts `{stream_id, parameters}` where parameters
is `encoder` or `low_delay`. It addresses only an attached viewer on the same
authenticated socket, requires its live view authority, requests a repairing
keyframe and applies on that keyframe. The default is `low_delay`. Selection
never changes capture settings, picture data or the shared encoder. Automatic
browser selection awaits paired hardware evidence; no user-agent guess is made.

Build removal (#146, D198/D232): the protocol desktop extension, native-streams
provider/owned-operation machinery and global-work lifecycle hooks are opt-in.
Desktop selects them together. Terminal-only builds keep their borrowed reader,
bounded control worker, socket authorization watchdog, transport binding,
priming and liveness. Wire declarations project browser capabilities explicitly:
desktop uses capability mask 8 on leg A and mask 64 on leg B; native-only declarations project
no browser bit. No frozen bytes or existing capability values change.

Durable writer identity survives build transitions: terminal ownership inserts
advance SQLite's AUTOINCREMENT sequence above both its retained sequence and
`wire_writer_clock`; native reservations advance the clock above both marks.
Both happen under the existing writer transaction and refuse the 31-bit
reservation limit before publishing a doubled even ID. Deleted terminal rows
and committed native reservations without rows therefore cannot be reused.

Control-session visibility adds input subtype5 (`active:u8`, exactly 0 or 1).
Only server lease transitions may originate it; browser input is refused.
Taking control clears old held input and shows the indicator before any event;
source reconnect restores a still-authorized lease without replaying input.
Retirement hides it. Ordinary held-input release/blur preserves the indicator.

## Native responsibility and permission diagnostics (#146)

Before framework access, the native companion establishes its own macOS
responsibility using the system `responsibility_spawnattrs_setdisclaim` hook
and `posix_spawn` with `POSIX_SPAWN_SETEXEC`. The replacement retains the PID,
process group and inherited stdio, so cancellation and EOF cleanup still address
the owned companion. The hook is system SPI, not a public SDK guarantee; resolve
it dynamically and refuse startup when it is unavailable or returns an error.
The responsibility/PID/pipe fixture is verified on macOS 27.0.1 with SDK 27.0.

`--check-permissions` follows that same native launch path, prints one JSON
object with boolean `screen_recording` and `device_control` keys from
`CGPreflightScreenCaptureAccess()` and `AXIsProcessTrusted()`, then exits before
AppKit setup. It never requests permissions, creates capture or injects input.
Observed on macOS 26.5.2: the first preflight of a signed bundle that is not
trusted still makes the system's accessibility service add that bundle to the
Accessibility list as denied, bound to its designated requirement. No window
appears. No Screen Recording or PostEvent entry is created. The person using
the Mac still turns the entry on; the preflight grants nothing.

`--capture-still <window-id> <owner-pid> <absolute.png>` is a local native
companion diagnostic. It follows the same responsibility bootstrap, requires
Screen Recording already granted, and validates the current window/PID pair
before invoking `/usr/sbin/screencapture` as its child. The output path must be
absolute and end in `.png`. It neither requests permissions nor injects input;
it is not exposed as a server action. This keeps diagnostic stills under the
installed identity instead of attributing them to a remote shell.

A local supervisor sets `INFRATERNAL_DESKTOP_COMPANION` to the absolute
executable path inside the installed signed bundle. It must be an owned regular
executable without shared write permissions; symlinks are refused. Remote action
bodies cannot set it. This path identifies the bundle and is never executed
directly: the Rust helper starts the bundle through LaunchServices with
`open -n -W -g`, passing a fresh mode-0600 Unix socket and PID-file path in its
mode-0700 private runtime directory. The bundle writes its PID before connecting
to that socket. The helper tracks the companion separately from the `open -W`
waiter and verifies the private launch arguments before signaling it during
bounded cleanup. Normal operation and `--check-permissions` both use this same
signed LaunchServices path; there is no loose-executable or embedded-companion
fallback. The bundle identifier remains `com.infraternal.desktop.helper`.
Signing and permission approval remain installation prerequisites, never
automated privacy or trust changes.

Sources: [Apple responsibility model](https://developer.apple.com/documentation/security/applying-launch-environment-and-library-constraints),
[spawn descriptor semantics](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/posix_spawn.2.html),
and [system-hook usage](https://raw.githubusercontent.com/chromium/chromium/main/base/process/launch_mac.cc).
