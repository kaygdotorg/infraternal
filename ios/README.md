# iOS join spike

`Infraternal.xcodeproj` contains a small SwiftUI app and a Packet Tunnel
extension for slice 1. The app sends device-start and redeem requests through
`URLSession`, opens the server's approval page with
`ASWebAuthenticationSession`, and passes the resulting invitation to the
extension. The extension creates a P-256 key with CryptoKit in Simulator or
the Secure Enclave on a device. Rust builds the CSR, checks the returned
certificate, opens the QUIC device link, and reports a ping and memory samples.

Build on `kayg@std` while holding `/tmp/infraternal-std-sim.lock`:

```sh
scripts/ios/build-xcframework "$HOME/.cache/codex-scratch/j1312/xcframework"
```

The script takes that lock itself, enters the repository's pinned Nix shell,
sets private `TMPDIR` directories inside Nix, creates the device and Simulator
XCFramework slices, generates the matching UniFFI Swift sources, and builds
the app for the assigned Simulator. Generated bindings and frameworks stay in
ignored `ios/Generated` and `ios/Frameworks` directories.

The app records `J1312_MEMORY` log entries from the extension's
`TASK_VM_INFO.phys_footprint` at idle and through each join stage. Capture the
Simulator log and run `scripts/ios/check-memory <log>`; the gate requires every
phase and enforces the 20 MiB Q3 ceiling. A successful link screen includes
the measured idle footprint, join peak, and QUIC ping.

This is a Simulator spike. Device signing still needs the owner's Apple team
identifier, a provisioning profile, and the Network Extension packet-tunnel
entitlement on the app and extension targets. The device Secure Enclave path
is present in Swift source; this spike does not sign, compile, or install a
device app.
