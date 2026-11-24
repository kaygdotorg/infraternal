# iOS bindings and network-extension memory prototypes (J1158, #580)

Throwaway measurement code for the iOS client grill
([docs/design/ios-client-grill.md](../../docs/design/ios-client-grill.md)).
Nothing here ships, and it is not part of the product workspace.

| Directory | What it is |
|---|---|
| `uniffi-core/` | six benchmark calls exported with UniFFI 0.32.2 proc macros |
| `bridge-core/` | the same six calls with swift-bridge 0.1.59 |
| `cabi-core/` | the same six calls as a hand-written C ABI, header by cbindgen 0.29 |
| `swift/` | the Swift timing harness, one executable per binding plus a Swift-only baseline |
| `ne-memory/` | a GotaTun device (the product's fork and pin, `ring` backend) with an in-memory TUN, sampling its own `phys_footprint` idle and under load |
| `results/` | raw output of the runs quoted in the grill |

The six calls: `noop`, `add(u64, u64)`, `frame_in(bytes)` (Swift lends a frame
to Rust), `frame_out(len)` (Rust hands a frame to Swift), `parse(text)` (ok
and error paths, the error becomes a Swift `throws`), and an async call that
completes on a Rust runtime thread and resumes a Swift `await`.

## How it was run (2026-11-24)

1. **Mac build VM** (`infraternal-macos-01-std`, macOS 26.5.2, Command Line
   Tools only, under `/tmp/mac-bench.lock`):
   `lockf -k /tmp/mac-bench.lock ./build-mac.sh <sdk-dir> <out-dir>`.
   The toolchain comes from `flake.nix` (the workspace's Rust 1.99.1 plus the
   `aarch64-apple-ios` and `aarch64-apple-ios-sim` standard libraries).
   `<sdk-dir>` holds `iPhoneOS.sdk` and `iPhoneSimulator.sdk` copied from
   std's Xcode 27.2; C build scripts (`ring`) compile against them through
   `SDKROOT`. This Mac's linker is older than those SDKs' library stubs
   (`arm64e.x1` in the `.tbd` files), so iOS targets are built as static
   libraries only and `ios-skip-cc.sh` skips GotaTun's unused cdylib link.
2. **std** (Mac Studio, Xcode 27.2, simulator `infraternal-01`, iOS 27,
   under `/tmp/infraternal-std-sim.lock`):
   `lockf -k /tmp/infraternal-std-sim.lock ./link-sim.sh <dir> <udid>` links
   the Swift harness and `ne-memory/sim-main.c` around the static libraries
   for the Simulator and for devices (size only), then runs them with
   `simctl spawn`.

Network: the only real sockets are two UDP ports on 127.0.0.1 between the
`ne-memory` phone and its peer child process. The tunnel's inner addresses
(10.99.0.0/24, 10.98.0.0/16 for idle peers) never reach an interface, and idle
peers have no endpoint, so they send nothing.
