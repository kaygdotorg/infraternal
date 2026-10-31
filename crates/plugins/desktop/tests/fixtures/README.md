<!-- Role: real AppKit fixtures and bounded evidence harness usage [D203,D208]. -->
# Native verification fixtures

These scripts target only the named test windows. Copy the fixtures, compiled
helper/client, and scripts into `~/infraternal-bench/app-windows` on a test Mac.
Acquire the shared Mac lock from the local host first and install an EXIT trap
that terminates your helper, fixture, occluder and any TextEdit process you
opened, removes only this directory, and releases the lock. Never exceed the
45-minute lease or change existing privacy entries. These fixtures do not approve
permissions or alter settings.

Compile `marker.swift` to `fixture`, `local-event.swift` to `local-event`, and
`open-menu.swift` to `open-menu` with `swiftc`. Create a private mode0700
`runtime` directory. Start the marker and helper, recording their PIDs for
cleanup. Create a file named `infraternal app-windows test.txt` and open it in a
new TextEdit instance. Run `native-evidence.py` and `idle-follow.py`; the latter
waits 62 seconds while draining frames. The helper must be launched under the
logged-in user with Screen Recording and Accessibility already granted.

For `occlusion.py`, compile `occluder.swift` to `occluder`. This version overlaps
the fixed marker window and targets its known CG coordinate250,1080 on the
2502×1326 test display. Adjust those fixture coordinates for another display.
It posts a key to the owned marker to ensure fresh frames while the magenta
other-process window overlaps it. Decode all saved frames and count magenta
pixels; the verified run had12 frames and0. The initial TextEdit-only occlusion
experiment had no fresh frames and is not pixel-exclusion evidence.

`scale.py` requires only the marker, an empty runtime for each of ten helper
instances, and a working directory containing `test-client.py`. The marker
redraws at30Hz while `animate.flag` exists. Readers drain continuously with a
130-second idle timeout. It samples15 seconds static and15 seconds moving,
then closes every connection and waits for all helper processes. Remove the
per-instance runtime directories before repeating. Start fresh helpers without
an already-used helper alive: that guest experiment failed to start new streams
until the prior helper exited. CPU includes only the helper and its two native
children, and excludes the fixture, WindowServer and GPU work. RSS includes
shared pages. Linear×50 output is an estimate, not measured capacity.

The native parser test is part of the crate. Run `cargo test -p
infraternal-plugin-desktop --features desktop --lib` on the Mac, and all-target
clippy with `-D warnings`. The local-input test uses an untagged synthetic event
through the real monitor path; it does not simulate physical hardware timing.

`mouse-up.py` tests releases without an incidental untagged move: it positions
the pointer using a tagged remote move, posts left/right/other untagged releases,
and checks rejection at0/1.75s and acceptance at2.25s. It first failed with
accepted=true immediately after release, before the event masks were fixed.

`responsibility-test.swift` compiles with `native/ResponsibleLaunch.swift` on
macOS. Launch the resulting executable through a parent pipe, write its original
PID followed by a newline to stdin, then close stdin and wait. It verifies the
system-reported responsible PID equals the companion PID and that the launch
retained the original PID and inherited pipes. It needs no capture permissions.
Compile the complete native companion with `native/Permissions.swift` too; its
`--check-permissions` mode must return exactly two JSON boolean fields and exit.
For a real permission check, use the installed signed bundle and the same local
companion path as production; do not request permissions from this fixture.

`native-pipe-faults.py` serves the real-pipe deadline tests through private
per-run symlinks: `pixel-reader.py` reports its PID and never drains input;
`reply-ordering.py` emits an old inventory reply before the next status reply.
The executable is checked in so concurrent tests never write the script they
are about to execute. Each run exclusively creates its receipt directory.

`measure-app-window.py` measures one real app window end to end (#146). Its
preferred transport launches the signed companion bundle itself with
`open -n -W -g --stdin FIFO --stdout FILE --stderr FILE --env
INFRATERNAL_DESKTOP_MEASURE=1 <bundle> --args --surface-capture`, so macOS
attributes capture to the bundle's own grant. Do not run capture under `sudo`
on a test Mac: a companion spawned by the Rust helper under `sudo` passed TCC as
its bundle, yet macOS asked the owner whether "sudo" may bypass the private
window picker (macOS 26.5, #146). `--socket` speaks
to a running helper instead, for the production socket path. Phases are
warmup, idle, typing (tagged text input through the companion), optional
scroll (tagged wheel events over a long document) and settled; the target app
must be frontmost for typing. Pass `--focus` when the idle phase must include an
active text caret; it clicks the target window center before warmup, so use it
only when that point is an editor. The Rust helper launches this same bundle through
LaunchServices with `open -n -W -g` and a fresh mode-0600 Unix socket in a
mode-0700 temporary directory; it refuses loose executables. In measurement
mode, companion metrics flow to the helper's stderr, including
LaunchServices-to-PID startup time. `summarize RUN STDERR` joins frame receipts with
the companion's METRIC lines by capture stamp: capture-to-encoded and
capture-to-client percentiles exclude sharp refreshes of the retained picture
(`surface_delivery fresh=false`), whose stamp age is not latency. CPU covers the
companion plus `VTEncoderXPCService`, `replayd` and `WindowServer`, which also
serve other clients. Decode `stream.h264` with any H.264 decoder for pixels.

`encoder-matrix.swift` lists every VideoToolbox encoder on the Mac and encodes a
decoded PNG of a real captured window (static, typing-sized damage and 8 px
scroll per frame, 60 Hz, one frame in flight) per codec/profile with the
companion's production session settings. It needs no permission and captures
nothing. It measures for the owner's encoder decision and chooses nothing.
