# iOS client and shared Rust client core: owner grill

**Job:** J1158 · **Issue:** #580 · **Status:** research and measurements only · **Decision owner:** kayg

This page prepares the owner grill for the native iOS client from D238. The
first slice the owner set on 2026-11-24 is mesh-only: a packet tunnel
extension, the Rust mesh node inside it, and enrollment with a passkey,
shipped through TestFlight. The rest of D238 (canvas, terminals, layout sync)
comes later and reuses the same core.

Each question below gives the options, what was measured and a
recommendation. The owner makes every decision (CLAUDE.md, "Foundational
choices"). The short list of decisions is at the end.

The prototypes and raw output are in
[research/ios-bindings](../../research/ios-bindings/README.md). Measured on
2026-11-24:

- **Mac VM** (`infraternal-macos-01-std`, macOS 26.5.2, Command Line Tools
  only): all builds, the macOS runs, and the iOS static libraries.
- **std** (Xcode 27.2, simulator `infraternal-01` on iOS 27): linking for iOS
  and the Simulator runs.

No iPhone was used. Device numbers are still open; see Q3.

---

## Summary

| Question | Measured | Recommendation |
|---|---|---|
| Q1 Crate split | `infraternal-protocol` and `infraternal-mesh` can be used unchanged. The node, link and canvas code needs to be split out of plugins that pull in `sqlx`, subprocesses and root paths. | Four new crates plus two FFI crates: one for the app, one for the extension. |
| Q2 Bindings | Each call costs 1 ns or less with any of the three. Byte buffers: UniFFI copies, at 4.5 µs for 4 KiB and 37 µs for 64 KiB in the Simulator. The C ABI takes 4 ns for any size. | UniFFI for the API surface, plus a small hand-written C ABI for per-frame byte buffers. Not swift-bridge. |
| Q3 Extension memory | The GotaTun engine peaks at 4.5 MiB under 1.4 Gbit/s of load and at 8.3 MiB with deep queues. The limit is 50 MiB (Apple staff figure; Apple does not document it). | Set the extension a 20 MiB budget and gate it on a real iPhone in slice 1. |
| Q4 Enrollment | Native passkeys need the server's domain in the entitlement when the app is signed. | Run the server's own approval page in `ASWebAuthenticationSession` (the existing device-approval flow). Keys go in a shared keychain access group. |
| Q5 SwiftUI layout | n/a | A thin Xcode project with all code in local Swift packages, shared between iOS and macOS. |
| Q6 Build and CI | Nix provides the Rust iOS targets (proven). The Mac VM's linker cannot link against the iOS 27.2 SDK. | Nix for Rust, Xcode on the build Mac (outside Nix), XCFramework as the hand-off. |

---

## Q1. Which crates form the client core, and how should they be split?

### What exists today

| Crate | Size (lines) | Client core? | Why |
|---|---|---|---|
| `infraternal-protocol` | 2.7k | **as-is** | A pure codec with no runtime dependencies and no I/O. Golden vectors already pair it with `packages/protocol`. |
| `infraternal-mesh` | 3.2k | **as-is** | Pure mesh coordination (policy, view, path choice). Depends on `serde` and `thiserror` only. |
| `infraternal-plugin-api` | 5.9k | after a feature cut | Usable with `socket-host` off. The mesh plugin turns `socket-host` on unconditionally, which pulls in `sqlx`. |
| `plugins/mesh` | 74.7k | **split** | See "The mesh node" below. |
| `plugins/remote` | 17.9k | **split** | Reusable client pieces: the QUIC/TLS client (`remote_quic.rs`, `remote_tls.rs`), `enrollment.rs`, `remote_renewal.rs`, `identity_rotation.rs`, `agent_link.rs`. Host-only pieces: `uninstall*`, `runtime_lock*`, `privilege_*`. |
| `infraternal-agent` | 52.6k | **split** | Only the dial-out link is reusable: `remote_client.rs`, `remote_supervisor.rs`, `remote_websocket.rs`, `remote_server_path.rs`, `wire.rs`, `transport.rs`. |
| `infraternal` (CLI) | 36.2k | **split** | The sign-in client (`sign_in.rs`: device-start, the approval link, redeem) and the join/CSR code in `remote.rs`. |
| `plugins/canvas` | 2.0k | **split** | `model.rs`, `reducer.rs` and `tiling.rs` are the pure layout tree. `socket.rs` and `store.rs` are server side. |
| `infraternal-shim` | 20.2k | later | The terminal state (`terminal.rs`, `terminal_native.rs`, libghostty-vt built with Zig) is gated to Linux and macOS. iOS needs its own build of the VT library. This belongs to the canvas slice, not slice 1. |
| `plugins/relay` | 2.2k | later | The client half (`client.rs`, `probe.rs`, `tls.rs`) can be reused. The relay path is Linux-only today; macOS has none either. |
| `infraternal-server`, `-db`, `-status`, `-session`, `-linux-tun`, `plugins/{proxy,release,backup,host-facts,ssh}` | | **server/host only** | SQLite, nftables, systemd/launchd, PTY hosting, subprocesses. |

Nothing in the tree targets iOS yet. There is no `cfg(target_os = "ios")`
anywhere, and the GotaTun dependency is gated to
`cfg(any(target_os = "linux", target_os = "macos"))`
(`crates/plugins/mesh/Cargo.toml`).

### The mesh node: what moves and what stays

The macOS node is almost ready for iOS. Its utun adapters are already
fd-based:

- `MacUtun`, `MacUtunTx` and `MacUtunRx` in `crates/plugins/mesh/src/macos_node.rs` implement GotaTun's `IpSend` and `IpRecv` over an `OwnedFd`, with the 4-byte AF header.
- They run `PacketFilter` in both directions.
- `BoundUdpFactory` wraps the handshake admission guard.

Inside an iOS packet tunnel, the same adapters would take the extension's
utun fd. The work is separating them from the code an extension cannot run:

- `OpenUtun::open` (the extension does not create its own utun);
- the `/sbin/ifconfig` and `/sbin/route` subprocesses, which become `NEPacketTunnelNetworkSettings` built in Swift;
- `/etc/resolver` plus `killall mDNSResponder`, which become `NEDNSSettings.matchDomains`;
- the root-only key file in `macos_key.rs`, which becomes the keychain (Q4);
- launchd and `/var/lib` state.

That code currently sits in `macos_node.rs`, a 4,972-line file that mixes the
engine, service and state.

### Options

- **(a) Lift whole plugins with features.** Compile `plugins/mesh` and `plugins/remote` for iOS behind new `ios` features. This is least work up front. The cost is that `sqlx` (unconditional in the mesh plugin), `openssl` (vendored) and the host code stay in the dependency graph, and every iOS build fights their `cfg` gates. It also risks dragging unneeded memory into the extension.
- **(b) Extract small platform-neutral crates** that the plugins and the iOS core both depend on. The Linux and macOS nodes then become thin hosts around them.
- **(c) A separate iOS-only copy.** Two mesh nodes would drift; this contradicts D238's single core.

### Recommendation: (b), with this split

| New crate | Content (moved, not copied) | Used by |
|---|---|---|
| `infraternal-mesh-node` | GotaTun wiring and the fd-based utun `IpSend`/`IpRecv`, `packet_filter`, `handshake_admission`, `candidates`/`candidate_walks`, `underlay_announce`, the DNS responder (`dns.rs`), `mesh_mtu`. Platform effects (addresses, routes, DNS routing, key storage) sit behind one `HostNet` trait. The macOS host implements it with ioctls and subprocesses, as today; iOS implements it by handing settings to Swift. No `sqlx`, no subprocesses. | Linux and macOS nodes, iOS extension |
| `infraternal-link` | The client side of leg B: QUIC with mTLS, the TCP/TLS and WebSocket fallbacks, the supervisor and retries, the node channel framing, enrollment and renewal wire models. Moved from `infraternal-agent` and `plugins/remote`. | infraternal agent, iOS extension |
| `infraternal-sign-in` | The device-start, approval-link and redeem client from `sign_in.rs`, plus CSR and join from `remote.rs`. Pure HTTP and crypto, with no file paths; storage is a trait. | CLI, iOS app |
| `infraternal-canvas-model` | `model.rs`, `reducer.rs`, `tiling.rs` from `plugins/canvas`, without `socket-host`. | server canvas plugin, iOS app (later slice) |
| `infraternal-tunnel-ffi` | The **extension's** static library: mesh node, link and protocol only. | iOS packet tunnel |
| `infraternal-client-ffi` | The **app's** static library: sign-in, protocol, canvas model, and later the terminal state and actions. | iOS (and later macOS) app |

**Two FFI libraries, not one.** The app and the extension are separate
processes, and each links its own copy of whatever it imports. The extension
must not carry the canvas, terminal or UI-side code against its memory limit.
The app talks to the extension through `NETunnelProviderSession.sendProviderMessage`
(status, peers, start and stop). Both sides encode those messages with
`infraternal-protocol`, so no new format is needed.

**The control link lives in the extension.** The server pushes `mesh.configure`,
rotation and policy over the node's own authenticated channel (`node_actions.rs`).
If that channel lived in the app, the tunnel would go stale whenever iOS
suspends the app. It belongs in the extension, together with the node's own
mesh identity, which is what the WireGuard iOS app and others do.

**TLS stack (foundational, owner decides).** Leg B currently uses vendored
OpenSSL for TCP/TLS (`remote_tls.rs`) and rustls with ring for QUIC (quinn).
On iOS, vendored OpenSSL means a second C build per Apple target and a
larger binary (not measured here; an estimate of a few MB). rustls with ring is already in the tree and matches D289
and D336 (ring is the only crypto library). Recommendation: use rustls only
in the client core. This needs the owner's call because it changes which TLS
implementation leg B runs on the client side.

---

## Q2. How does Swift call Rust?

Three prototypes export the same six calls
([research/ios-bindings](../../research/ios-bindings/README.md)):

- UniFFI 0.32.2 (proc macros);
- swift-bridge 0.1.59;
- a hand-written C ABI with a header generated by cbindgen 0.29.4.

The Swift harness times each call over 7 rounds and reports the median.
Builds use the release profile with fat LTO and one codegen unit.

### Call overhead in the iOS Simulator (std, iOS 27, Apple silicon), ns per call

| Operation | UniFFI | swift-bridge | C ABI |
|---|---:|---:|---:|
| no-op | 1.5 | 0.7 | 0.7 |
| `add(u64, u64)` | 8.5 | 7.7 | 7.9 |
| bytes in, 64 B | 132 | 4.5 | 4.7 |
| bytes in, 4 KiB | 4,531 | 5.4 | 4.5 |
| bytes in, 64 KiB | 37,072 | 4.0 | 4.0 |
| bytes out, 64 B | 404 | 62 | 5.7 |
| bytes out, 4 KiB | 4,858 | 107 | 32.6 |
| bytes out, 64 KiB | 42,232 | 3,917 | 504 |
| parse, ok | 50 | 94 | 10.7 |
| parse, error to Swift `throws` | 514 | 189 | 31 |
| async: Rust task completes, Swift `await` resumes (µs) | 19.3 | 38.1 | 16.2 |

macOS arm64 on the Mac VM gives the same picture. For example, bytes in at
4 KiB: UniFFI 3,478, swift-bridge 3.9, C ABI 3.1 ns. See
`results/calls-macos-*.jsonl`.

What the numbers mean:

- **Bytes:** UniFFI serialises `Vec<u8>`/`Data` into its own buffer, about
  1 ns per byte in each direction. swift-bridge and the C ABI pass a borrowed
  pointer and a length, so the cost stays flat at about 4 ns whatever the
  size. "Bytes out" for the C ABI writes into a buffer Swift owns and reuses;
  swift-bridge allocates a `Vec` on every call.
- **D238 budget:** hot paths cross once per frame. Fifty terminals at 120 Hz
  with 4 KiB frames is 6,000 crossings a second. With UniFFI that is
  6,000 × 4.5 µs ≈ 27 ms of CPU per second (2.7% of a core). With the C ABI
  it is about 0.03 ms. For control calls (sign-in, status, peers, settings)
  every option is negligible.
- **async:** UniFFI and the C ABI both resume a Swift `await` from a Rust
  runtime thread in 16–19 µs. swift-bridge takes twice as long. With a timer
  in the call, tokio's 1 ms timer resolution dominates every option; a first
  version of this row measured exactly that and was redone.

### Size, build and maintenance

| | UniFFI | swift-bridge | C ABI + cbindgen |
|---|---|---|---|
| Stripped iOS device executable, minus the Swift-only baseline (70 KB) | +500 KB | +542 KB | +388 KB |
| Generated glue (lines) | 817 Swift + 579 C header | 1,347 + 41 Swift + 13 C header | 75 C header (Swift wrappers by hand) |
| Errors | Rust enum → Swift `Error` enum with fields | `Result<T, String>` → `throws RustString` | status code + out-parameter, wrapped by hand |
| async | native `async fn` → Swift `async` | supported, but slower (above) | callback + `withCheckedContinuation`, by hand |
| Records, enums, objects, callbacks | generated, including callback interfaces (Swift implements a Rust trait) | partial | by hand |
| Generator bugs hit in 6 functions | none | two: `Result<u64, _>` panics in the build script (`todo!()`), and a `&str` argument with a `Result` return emits Swift that does not compile | n/a |
| Licence / version / last release | MPL-2.0 / 0.32.2 / 2026-09-23 | Apache-2.0 or MIT / 0.1.59 / 2026-01-06 | MPL-2.0 / 0.29.4 / 2026-06-09 |
| Who uses it | Mozilla ships it in Firefox for iOS | pre-1.0, thin maintenance | n/a |

The +388–542 KB includes Rust's standard library and tokio, which every
option pays. The differences between the three are 100–150 KB.

### Options

- **(a)** UniFFI for everything.
- **(b)** A hand-written C ABI for everything.
- **(c)** swift-bridge.
- **(d)** UniFFI for the API surface, plus a few hand-written C functions for per-frame byte buffers.

### Recommendation: (d)

UniFFI generates the bulk of the surface, correctly and with idiomatic Swift:
sign-in, sessions, status, settings, errors, async, and callbacks from Rust
into Swift. That surface is where hand-written glue would cost the most
review time.

Fewer than about 10 C functions with a borrowed pointer and length cover
what D238 calls "byte buffers per frame": frame in, frame out into a buffer
Swift owns, and later the packet batches in Q3's packetFlow fallback. Those
functions are cheap to review, the hot-path cost is 4 ns instead of 4–40 µs,
and cbindgen keeps the header honest.

swift-bridge is rejected. It hit two generator bugs in six functions, it is
slower than the C ABI on its strong side and slower than UniFFI on async, and
its maintenance is thin.

---

## Q3. Does the mesh node fit the network extension's memory limit?

### The limit (Apple sources)

- Apple does not document it. Asked for documentation, Apple DTS answered
  "No, but see this thread"
  ([forums/thread/763392](https://developer.apple.com/forums/thread/763392)).
- Apple DTS (Quinn) measured the limits on iOS 16 and published them: packet
  tunnel 50 MiB, app proxy 15, filter control 50, filter data 50, DNS proxy
  15. His note: "These limits have changed in the past and may well change
  in the future… You should not hard code knowledge about these limits",
  and they may be lower on older devices. Apple DTS later added: "AFAICT the
  limits are unchanged on iOS 26"
  ([forums/thread/73148?page=2](https://developer.apple.com/forums/thread/73148?page=2)).
- History: 15 MiB up to iOS 14. Tailscale wrote "iOS 15 launched and quietly
  gave us 35MB more" ([tailscale.com/blog/go-linker](https://tailscale.com/blog/go-linker)).
- macOS imposes no such limit on network extensions
  ([forums/thread/682778](https://developer.apple.com/forums/thread/682778)).
- Over the limit, jetsam kills the extension. Forum crash logs show
  `EXC_RESOURCE RESOURCE_TYPE_MEMORY … limit=50 MB`
  ([forums/thread/763586](https://developer.apple.com/forums/thread/763586)).
  This comes from search snippets, not a verified full log.
- Mullvad replaced wireguard-go with GotaTun in its iOS app (changelog
  "[2026.7] … Replace WireGuardGo with GotaTun",
  [mullvadvpn-app ios/CHANGELOG.md](https://github.com/mullvad/mullvadvpn-app/blob/main/ios/CHANGELOG.md)),
  so the engine already runs inside an iOS packet tunnel in production.
  Mullvad publishes no memory figures.

### Measured: the GotaTun engine

The `ne-memory` harness runs one GotaTun device the way the macOS node does:

- the product's fork and pin `e6efb96`, with the `ring` backend;
- one current-thread tokio runtime;
- an in-memory TUN that generates 1280-byte packets;
- a peer child process that echoes them back over loopback UDP.

The harness reads its own `phys_footprint`, the figure iOS enforces the limit
against, through `task_info(TASK_VM_INFO)`. Each load phase lasts 20 s.
"Window" is the number of packets kept in flight.

| Run | macOS idle | macOS load peak | macOS echo | Simulator lifetime peak |
|---|---:|---:|---:|---:|
| 1 peer, window 256 | 3.58 MiB | 4.47 MiB | 1,481 Mbit/s | 4.06 MiB |
| + 50 idle peers | 3.45 MiB | 4.59 MiB | 1,360 Mbit/s | 4.25 MiB |
| + 500 idle peers | 5.28 MiB | 6.02 MiB | 1,454 Mbit/s | 5.28 MiB |
| + 50 idle peers, window 2048 | 4.86 MiB | 8.25 MiB | 1,554 Mbit/s | 5.38 MiB |

The process baseline before the device exists is 0.84 MiB. Each configured
peer without traffic costs about 3.7 KiB. Deeper queues are what raise the
peak. The Simulator reached only about 0.5 Gbit/s on a busy std, so its peaks
are lower. Raw data: `results/ne-memory-{macos,sim}.jsonl`.

### What the full node adds (estimated, not yet measured)

- **Packet filter:** 67 KiB per peer once it has a flow, from the documented
  sizes in `packet_filter.rs`. At 10–50 active peers that is 0.7–3.4 MiB.
  The filter's documented bound of 288 MiB at 4,096 active peers would kill
  the extension. On iOS the active-peer count needs a cap derived from the
  budget, or the tables need to be smaller.
- **Control link:** a QUIC connection (quinn and rustls) plus its tokio
  tasks. Estimate: low single-digit MiB, to be measured in slice 1.
- **DNS responder and policy snapshot:** small at our scale (D393: 1,000
  peers designed for).
- **UDP buffers:** the Linux node asks for 7 MiB socket buffers
  (`UDP_BUFFER_BYTES`). That is kernel memory. Whether iOS charges it to the
  extension must be checked on a device; the safe default on iOS is the
  system default size.
- **Swift side of the extension:** the `NEPacketTunnelProvider` subclass and
  Foundation. This was not measured here and must be measured on a device;
  the total below assumes it stays under 8 MiB.

A rough total of 15–20 MiB against a 50 MiB limit leaves a wide margin, as
long as the extension links only `infraternal-tunnel-ffi` (Q1) and the
filter's active-peer tables are capped.

### How packets reach the engine on iOS

- **(a) Use the extension's utun file descriptor** and reuse `MacUtunTx` and
  `MacUtunRx` unchanged. The fd is found by scanning descriptors for
  `UTUN_OPT_IFNAME`. The WireGuard iOS app does this, and so do apps built on
  it. It is zero-copy and uses the same code path as the macOS node. Risk:
  the method is not a documented Apple API.
- **(b) `NEPacketTunnelFlow.readPackets` / `writePackets`.** This is the
  documented API. Every batch of packets crosses Swift↔Rust as `Data`, which
  costs a copy plus the hand-written C ABI calls from Q2, and it needs a new
  `IpSend`/`IpRecv` adapter.

**Recommendation:** (a), behind the same `IpSend`/`IpRecv` traits, with (b)
written as the fallback the extension selects if fd discovery fails. Slice 1
measures both on the owner's iPhone.

### Recommendation for the budget

- Set the extension a **20 MiB phys_footprint budget**, 40% of the limit
  Apple staff measured.
- Slice 1 measures it on the owner's iPhone 16 Pro Max (idle, under an
  iperf-style load, 50 peers) through the extension's own `task_info`
  sampling, which this harness already implements.
- Make the same probe a gate: a Simulator run that fails above the budget.

---

## Q4. Enrollment with passkeys, and how the extension gets its keys

### Passkeys on iOS

- **The native API** is `ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier:)`,
  with `createCredentialRegistrationRequest` and `createCredentialAssertionRequest`,
  run through `ASAuthorizationController`.
- **It needs an associated domain.** It only works for domains listed in the
  app's `com.apple.developer.associated-domains` entitlement under
  `webcredentials:`, with an `apple-app-site-association` file served by that
  domain. Apple: "Your app can't use passkeys to authenticate for services
  that you haven't configured as the app's associated domains"
  ([Supporting passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)).
- **The domains are fixed when the app is signed.** The only variation is
  `?mode=managed` for MDM devices
  ([associated-domains entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.associated-domains)).
- **That rules out the native API for self-hosted servers.** infraternal is
  self-hosted, so the app cannot know every server's domain at build time.
  Native passkeys would work only for domains we list ourselves, such as the
  owner's `ssh.kayg.org`.

### Options

- **(a) The server's own page in `ASWebAuthenticationSession`.** The app
  runs the existing device-approval flow (the CLI's `sign_in.rs`):
  1. The app POSTs `/auth/device-start`.
  2. It opens the approval link in `ASWebAuthenticationSession`.
  3. The user signs in with a passkey on the server's own page.
  4. The app polls `/auth/device-redeem`.

  Then the extension's node joins, with a CSR, as the CLI's `infraternal up`
  does. Strengths: it works for every server with no entitlement, it uses
  the same server code as the CLI, and the passkey ceremony stays on the
  server's origin (D239 Q33: "auth always happens on the server's own
  page"). Apple staff point to this API for signing in to services you do
  not own ([forums/thread/725763](https://developer.apple.com/forums/thread/725763)).
  That WebAuthn works inside `ASWebAuthenticationSession` with the page's own
  RP ID is stated by passkeys.dev
  ([passkeys.dev/docs/reference/ios](https://passkeys.dev/docs/reference/ios)),
  not by Apple, so slice 1 must test it on a device.
- **(b) Native passkeys for a fixed list of domains,** with a fallback to (a)
  for any other server. It gives a slightly smoother sheet for the owner's
  own servers, at the cost of two code paths plus an AASA file and a release
  for each listed domain.
- **(c) Approval from another signed-in device:** a code or QR shown on the
  iPhone and approved from the PWA or the CLI. This is a useful extra path,
  and it is the same device-start flow.

**Recommendation:** (a) for slice 1, which gives (c) for free because it is
the same server flow. Revisit (b) only if the web sheet feels wrong on the
device.

### Where the keys live

| Secret | Where | Why |
|---|---|---|
| Mesh WireGuard key (X25519) | Keychain item in a **keychain access group** shared by the app and the extension, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | The extension must read it when iOS starts the tunnel on demand or after a reboot, once the phone has been unlocked once ([kSecAttrAccessibleAfterFirstUnlock](https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlock)). `ThisDeviceOnly` keeps it out of backups. Access groups are limited to one team ([Sharing keychain items](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)). |
| Node identity for leg B (device certificate key) | Same access group. Option: a **Secure Enclave P-256** key | The Secure Enclave holds only P-256 keys and cannot import existing keys ([Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)), so it cannot hold the X25519 mesh key. It can hold the TLS client key, if the leg-B certificate uses P-256 and rustls signs through a callback into the Security framework. Apple staff say Secure Enclave items can be shared through an access group ([forums/thread/674312](https://developer.apple.com/forums/thread/674312)); sharing with an extension specifically is called "reasonable", not guaranteed ([forums/thread/810676](https://developer.apple.com/forums/thread/810676)). |
| API credential from sign-in | App-only keychain item | The extension does not need it. |
| Server URL, node id, non-secret settings | `NETunnelProviderProtocol.providerConfiguration` and the app group container | Apple staff: "providerConfiguration isn't really the place to be storing secrets" ([forums/thread/680013](https://developer.apple.com/forums/thread/680013)). Secrets go in the keychain and are referenced through `passwordReference`, as the WireGuard iOS app does. |

**Who generates the keys.** The extension generates the mesh key through the
Rust core, and the private key never leaves the extension. It returns only
the public key and the CSR to the app through `sendProviderMessage`. The app
completes the sign-in in the browser sheet and hands back the join token.
That keeps the private key in one process.

The macOS node chose a root-only file over the keychain because keychain
ACLs trust a code identity, not a uid (`macos_key.rs`). On iOS that is
exactly what we want: the access group is tied to our signed team.

---

## Q5. SwiftUI structure shared between iOS and macOS

The owner's rule from 2026-11-24: no macOS GUI now, but SwiftUI written so
that iOS and macOS share it, and private macOS APIs are fine on the Mac.

```
apps/apple/
  Infraternal.xcodeproj        thin: targets, entitlements, signing only
  Packages/
    InfraternalCore/           Swift package: binaryTarget InfraternalTunnelFFI.xcframework
                               and InfraternalClientFFI.xcframework, the UniFFI Swift,
                               and small Swift wrappers over the C hot-path calls
    InfraternalUI/             SwiftUI views and view models; iOS and macOS;
                               #if os(macOS) only at the edges (window chrome, menus)
    TunnelProvider/            the NEPacketTunnelProvider subclass: settings builder,
                               utun fd discovery, packetFlow fallback, IPC handling
  App-iOS/                     @main App, Info.plist, entitlements
  Tunnel-iOS/                  packet tunnel app extension target (links TunnelProvider)
  (later) App-macOS/, Tunnel-macOS/
```

- Every source file lives in a package, so `swift build` and `swift test`
  run without the project, and iOS and macOS compile the same code.
- **Entitlements:**
  - app: `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`), App Groups and a keychain access group;
  - extension: the same three;
  - the app gets Associated Domains only if Q4 (b) is chosen.
- **macOS later.** The macOS packet tunnel would be a system extension for
  Developer ID distribution, or an app extension for the Mac App Store. The
  existing launchd daemon, which already runs a utun node as root, stays
  until then.
- **Project file (tooling choice).** Options:
  - a checked-in `.xcodeproj`, kept thin;
  - a generator (XcodeGen or Tuist), which avoids merge conflicts in `project.pbxproj`.

  Recommendation: the thin checked-in project, because the packages hold all
  the code and the project rarely changes. A generator is another tool in
  the build.
- **Reuse rule.** `packages/ui` holds the web components. The design tokens
  (colours, radii, spacing, motion) should be exported to Swift from the same
  source, so the native and web chrome match (TASTE.md). This is a follow-up,
  not slice 1.

---

## Q6. Building the Rust core for iOS in our Nix setup, and CI

### Measured

- **Nix provides the Rust side.** [research/ios-bindings/flake.nix](../../research/ios-bindings/flake.nix)
  uses the root flake's pins (same `flake.lock`) and `rust-bin.stable."1.99.1"`
  with the targets `aarch64-apple-ios` and `aarch64-apple-ios-sim`. It built
  every prototype.
  - Cold build of the prototype workspace for macOS: 77–86 s. Each iOS
    target then took 9 s on the Mac VM (`results/build-times.txt`).
  - The product's GotaTun builds for both iOS targets with `ring` once the
    iOS SDK is visible to its C build (`SDKROOT`).
- **Nix cannot provide Xcode or the iOS SDK.** The nixpkgs manual says
  "Xcode can't be packaged with Nix". `xcodeenv` only links an installed
  Xcode ([nixpkgs ios.section.md](https://github.com/NixOS/nixpkgs/blob/master/doc/languages-frameworks/ios.section.md)),
  and `darwin.xcode_*` needs a manual download through `requireFile`.
- **The Mac VM cannot link for iOS.** Its Command Line Tools linker rejects
  the iOS 27.2 SDK stubs (`unknown architecture … arm64e.x1-ios`). The
  prototypes therefore built iOS static libraries there, from an SDK copied
  out of std's Xcode, and std's Xcode linked them.
- **GotaTun forces a link.** Its manifest declares a `cdylib`, and cargo
  links that even when GotaTun is only a dependency, so a static-library-only
  build still needs a working iOS linker. The prototype skipped it with a
  stand-in linker (`ios-skip-cc.sh`). The real fix is a small fork patch
  that drops the cdylib or moves it behind a feature.
- **Both shells put nix's clang wrapper first in PATH,** and it misbuilds
  Apple targets: it linked the Simulator build against nix's macOS
  `libiconv`. Apple targets must use `/usr/bin/clang`, set through
  `CC`/`AR`/`CARGO_TARGET_*_LINKER` as `build-mac.sh` does. The repository's
  `.cargo/apple-cc.sh` already does the same for macOS, after the same
  `libiconv` failure (#265); the iOS targets need the same wrapper.

### Recommended pipeline

1. `nix develop` (Rust with the iOS targets added to the root flake's dev
   shell, as the macOS target already is) →
   `cargo build --release --target aarch64-apple-ios{,-sim} -p infraternal-{tunnel,client}-ffi`
   produces static libraries.
2. `uniffi-bindgen` (pinned in the workspace, as in the prototype) writes the
   Swift glue; cbindgen writes the hot-path header.
3. `xcodebuild -create-xcframework -library … -headers …` creates one
   XCFramework per FFI crate, for device plus Simulator. Apple says not to
   combine slices with `lipo`
   ([Creating a multi-platform binary framework bundle](https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle)).
   The Swift package consumes it as a path `binaryTarget`.
4. `xcodebuild` builds the app and the extension, runs the Simulator tests,
   and runs the Q3 memory gate.
5. Signing and TestFlight upload: the owner's account; not done in this job.

### Build host (owner and maintainer)

| Option | Pros | Cons |
|---|---|---|
| Install Xcode 27.2 on the Mac VM | It is the build VM already, and it is under the Mac lock | Xcode takes many GB (not measured here) and the VM has 22 GB free on a wear-limited SSD |
| Build on std (owner's Mac Studio) | Xcode and the simulator are already there | It is the owner's machine; it has no Rust today (a job-local rustup or Nix would be new there); it is shared with calternal |
| A second Mac VM for iOS builds | Clean separation | More disk on the same SSD |

Recommendation: install Xcode on the Mac VM after freeing disk, or grow the
VM's disk. iOS CI is one job at a time anyway, under the existing Mac lock.

---

## Decisions for the owner

| # | Decision | Recommendation | Where |
|---|---|---|---|
| 1 | Swift↔Rust bindings | UniFFI for the API surface, plus fewer than ~10 hand-written C functions with pointer and length for per-frame bytes. Not swift-bridge. | Q2 |
| 2 | Crate split | Extract `mesh-node`, `link`, `sign-in`, `canvas-model`; one FFI crate for the extension and one for the app | Q1 |
| 3 | Where the control link runs | In the packet tunnel extension, with the node's own identity | Q1 |
| 4 | TLS for the client core | rustls with ring only, no vendored OpenSSL on iOS | Q1 |
| 5 | How packets reach GotaTun | The utun fd with the existing `MacUtunTx`/`Rx`, with `packetFlow` as fallback; measure both on the iPhone | Q3 |
| 6 | Extension memory budget and gate | 20 MiB `phys_footprint`, measured on the owner's iPhone in slice 1, then gated in the Simulator. Cap packet-filter tables on iOS. | Q3 |
| 7 | Enrollment | The server's own approval page in `ASWebAuthenticationSession` (the existing device-start/redeem flow); no native passkeys in slice 1 | Q4 |
| 8 | Key storage | Shared keychain access group, `AfterFirstUnlockThisDeviceOnly`; the extension generates the mesh key. Whether the leg-B identity key goes in the Secure Enclave (P-256) is a yes/no call. | Q4 |
| 9 | Minimum iOS version | iOS 26. The owner's iPhone runs 27 and there are no other users yet (2026-11-20 rule), and Apple staff confirmed the 50 MiB limit for 26. | Q3, Q5 |
| 10 | Xcode project file | A thin checked-in `.xcodeproj` with all code in local Swift packages; no generator | Q5 |
| 11 | iOS build host | Xcode on the Mac VM (needs disk), not std | Q6 |
| 12 | GotaTun fork patch | Drop or feature-gate the `cdylib` so iOS static builds need no link | Q6 |

### Not answered here (needs a device or a later slice)

- Device numbers for Q3 (Swift side, link, UDP buffers, both packet paths).
- WebAuthn inside `ASWebAuthenticationSession` on the device (Q4).
- Building libghostty-vt for iOS (terminal state, canvas slice).
- D238's 10/25/50-terminal Metal spike.
