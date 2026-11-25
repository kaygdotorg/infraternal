# Shared Rust client core: the split plan

**Job:** J1171 · **Issue:** #580 · **Decisions:** D238, the owner's grill answers of 2026-11-24 on #580 · **Status:** plan only; no code has moved · **Base:** dev `034ed2ebf`

This page turns the crate split the owner accepted in the
[iOS client grill](ios-client-grill.md) (Q1) into a list of moves you can
build. For each new crate it names:

- the modules and items that move, and where they come from;
- what stays server-only or host-only;
- the dependency graph and feature flags;
- the Rust surface Swift calls in slice 1.

It then gives the server change for P-256 identity keys, the migration order
as small PRs, and how the core gets built for iOS on kayg@std.

Slice 1 is mesh-only: a packet tunnel extension running the Rust mesh node,
enrolment through the server's own page in a system web sheet, and the
identity key in the Secure Enclave. Owner answers that this plan builds on:

- UniFFI for the API, plus fewer than 10 hand-written C functions for
  per-frame bytes.
- Four core crates (`mesh-node`, `link`, `sign-in`, `canvas-model`), with one
  FFI crate for the extension and one for the app.
- The control link runs inside the extension.
- TLS is rustls with ring on iOS.
- The extension has a 20 MiB budget.
- Minimum iOS 26.
- All iOS builds run on kayg@std.

The owner still decides the open questions at the end.

---

## Measured for this plan (2026-11-24)

The checks ran on the Mac VM (`infraternal-macos-01-std`, Command Line Tools
only), under the Mac lock. They used the iPhoneSimulator 27.2 SDK copied from
std's Xcode and the J1158 toolchain flake (`research/ios-bindings`, Rust
1.99.1 with the iOS targets). Each is `cargo check --target
aarch64-apple-ios-sim` with nothing linked, `IPHONEOS_DEPLOYMENT_TARGET=26.0`,
and a cold target. std itself has Xcode 27.2 but no Rust (checked on
2026-11-24), so running the check there would first need a toolchain install.
That install is an open question (Q7).

| What was checked | Result | Time |
|---|---|---:|
| `infraternal-protocol` + `infraternal-mesh` (today's crates, unchanged) | **builds** | 5 s |
| The extension's proposed dependency set: GotaTun fork `841ef3e` (`device`, `ring`), quinn 0.11 (`rustls-ring`), rustls 0.23 (`ring`), ring, tokio (`rt`, `net`, `time`, `sync`, `macros`, `io-util`; no `rt-multi-thread`), nix (`net`, `ioctl`, `poll`, `time`, `uio`), zeroize, ipnetwork, hickory-proto, plus the two crates above | **builds**; 191 crates, none of them openssl, sqlx or aws-lc | 16 s |
| `infraternal-plugin-mesh --no-default-features --features agent` (today) | **fails**: `openssl-src 300.6.1` panics in its build script for this target (`index out of bounds`, lib.rs:669). The same build also compiles `sqlx-sqlite` and `infraternal-linux-tun` for iOS. | 19 s |
| `-p gotatun` inside the workspace | cargo panics (`did not find features for gotatun`). The mesh plugin gates GotaTun to `cfg(any(target_os = "linux", target_os = "macos"))`, so GotaTun is not part of the iOS dependency graph at all. | 1 s |
| `infraternal-plugin-remote` (default features) | builds, but only because `default = []` leaves out all the client code. The `transport` feature turns on `openssl` and `tokio-openssl` without a switch to avoid them. | 4 s |

What this shows:

- The new crates' dependency set already builds for the Simulator.
- Today's plugins cannot be used on iOS through features alone: vendored
  OpenSSL does not even build for the Simulator target. That makes option (a)
  of grill Q1 a dead end as well as a costly one.

Receipts are on hd01 in `~/.cache/codex-scratch/j1171/evidence/ios-sim-check/`:
`summary.txt`, the logs, the probe's `Cargo.toml` and the two scripts. The
Mac VM's copies, the SDK and the targets were deleted afterwards.

---

## The crates at a glance

```
                      ┌──────────────────────── iOS packet tunnel extension ──┐
                      │  infraternal-tunnel-ffi  (staticlib, UniFFI + C ABI)  │
                      │      │            │                │                  │
                      │      ▼            ▼                ▼                  │
                      │ mesh-node ──▶ infraternal-mesh   link ──▶ protocol    │
                      │      │                             │                  │
                      │   gotatun, ring, tokio(rt)      quinn, rustls, ring   │
                      └───────────────────────────────────────────────────────┘
                      ┌──────────────────────── iOS app ──────────────────────┐
                      │  infraternal-client-ffi  (staticlib, UniFFI)          │
                      │      │            │                │                  │
                      │      ▼            ▼                ▼                  │
                      │   sign-in      protocol    canvas-model (later slice) │
                      └───────────────────────────────────────────────────────┘

  Linux/macOS hosts keep today's crates. Each one depends on the new crates instead of owning the code:
    plugins/mesh   ──▶ mesh-node        (host effects stay: utun open, routes, DNS, launchd, nft)
    plugins/remote ──▶ link             (OpenSSL TCP/TLS and the server side stay until ported)
    infraternal-agent ──▶ link          (plugin host, sessions, shim stay)
    infraternal (CLI) ──▶ sign-in, link (files, terminal output, uid checks stay)
    plugins/canvas ──▶ canvas-model     (socket.rs, store.rs stay)
```

Rules for every new crate:

- `license = "AGPL-3.0-only"`, through `license.workspace = true`.
- `#![deny(unsafe_code)]` everywhere except `mesh-node`'s fd module and the
  FFI crates' C ABI module. Those two get a scoped `allow`, as
  `plugins/mesh` does today.
- Each crate sets its own `tokio` and `nix` feature lists. It never inherits
  the workspace lists, which turn on `process` and `signal` (tokio) and
  `fs`, `term`, `process`, `user` (nix).
- No `openssl`, `sqlx`, `std::process::Command`, `tokio/rt-multi-thread`,
  file paths, uid checks or environment variable reads in any crate the FFI
  crates link. Hosts pass those things in.

---

## 1. `infraternal-mesh-node`: the mesh node engine

This crate is the GotaTun device, its packet adapters, the packet filter,
handshake admission, the candidate walks and the node state machine. Platform
effects sit behind two traits that the host implements: `HostNet` (addresses,
routes, DNS, MTU probes) and `NodeStore` (saved state and the private key).

### Moves as-is from `crates/plugins/mesh/src` (std, serde, tokio or gotatun only)

| Module | Notes |
|---|---|
| `dataplane.rs` | `Config`, `Chunk`, `Identity`, `PeerPolicy`. The coordinator uses it too, so `plugins/mesh` re-exports it. |
| `access_updates.rs` | `apply()` is the node side. It uses `infraternal_plugin_api::MAX_ACTION_BYTES`; see "plugin-api" below. |
| `candidates.rs`, `candidate_walks.rs` | `lan_addresses` uses the UDP-connect trick, which works inside an extension. |
| `listen_port.rs` | `from_environment` stays in the host. The engine takes the port as a value. |
| `underlay_announce.rs` | On Linux and macOS it is fed by the route listeners. On iOS Swift feeds it (`NWPathMonitor` → `Tunnel::network_changed`). |
| `handshake_admission.rs` | Its nix and current-thread use is test-only. |
| `packet_filter.rs` | Add a cap on active-peer tables, set from the platform budget: the documented 288 MiB bound at 4,096 peers does not fit the extension (grill Q3). |
| `tunnel_dns.rs`, `macos_node/user_mode.rs::answer_resolver_query` | DNS answered inside the packet path. iOS needs this because the extension cannot bind port 53 on the mesh address. |
| `macos_node/peer_stats.rs`, `macos_node/dns_state.rs` | Pure. |
| `enrolment.rs` | Once `openssl::sha::sha256` (lines 35, 37) becomes `ring::digest::SHA256`. `agent_key` is the SHA-256 of the identity's public key DER, so a P-256 SPKI fits as it is. |
| `node_presentation.rs` | Without `engine_health` (Linux-only, line 330). |

### Moves after a split

| Source | Into mesh-node | Stays in the host |
|---|---|---|
| `mesh_mtu.rs` | constants, `RouteBudget`, `interface_mtu`, `mtu_for_route`, `mtu_for_inner_budget`, `parse_macos_*` | `EndpointProbe::route_mtu`: `/sbin/route` and `/sbin/ifconfig` (lines 177–190) on macOS, netlink on Linux. Becomes `HostNet::route_mtu`. |
| `dns.rs` | `Records`, `response`, `response_for_records` | `Resolver` (line 718 on): a thread-based server bound on the mesh address |
| `node_state.rs` | `State`, the authority record merge and split (lines 1299–1420), `RotationSecret` | `Store` (0700 directories, `Flock`, `O_NOFOLLOW`, uid, `statfs`) becomes the host's `NodeStore` implementation. The Linux machine id stays too. |
| `node_actions.rs` | `ACTIONS`, `CONTROL_ACTIONS`, `DESCRIPTOR`, `Request`, `parse_action`, `peer_page`, and a platform-neutral `MeshNodeActions` holding the `AgentPlugin` impl's dispatch | `MeshNodePlugin`'s `ComponentPlugin` impl, the `Owner` restore and the `cfg(target_os)` branches (lines 1076–1305) |
| `macos_node/walks.rs` | `run_worker` loop, `refresh_walks`, `step_walks`, `set_endpoint`, `rehandshake` | `start_underlay_listener` (PF_ROUTE) |
| `macos_node/underlay.rs` | `UnderlayBooks`, `ChangeBook` | the PF_ROUTE socket, `rt_msghdr`, `getifaddrs` |
| `macos_node.rs` | see the next table | see the next table |

### `macos_node.rs`: the engine moves, the Mac host stays

The file is 4,945 lines on dev (199,493 bytes, cap 200,000). J1169's branch
`j1169-macos-route-client` (head `3b94e340b`) splits it:

- the tests move to `macos_node/tests.rs`, which brings the file to 129,308 bytes;
- a new `macos_node/subnet.rs` holds the subnet-route code.

The line numbers below are from dev and will move once J1169 merges.

| Into mesh-node (`engine/`) | Stays in `plugins/mesh` (macOS host) |
|---|---|
| `MacUtunTx`, `MacUtunRx`, renamed `UtunTx`/`UtunRx` (336, 369): `AsyncFd<OwnedFd>`, the 4-byte AF header, `PacketFilter`, tunnel DNS. This is the shape of the extension's utun fd. | `OpenUtun::open`/`open_kernel` (211, 224): a PF_SYSTEM socket or the helper |
| `MacUtun` (266) without `helper_applied`; `utun_family`, `parse_utun_payload` (914, 927) | `route`, `remove_routes` (423, 460): `/sbin/route` |
| `BoundUdpFactory` (149), `bind_udp` (1467); `mac_connected` becomes a config value, not an environment variable | `configure_interface`, `configure_owned_interface`, `set_interface_mtu`, `run_ifconfig` (475–527) |
| `installed_keys`, `Counters` (175, 184); `route_addresses`, `route_mtus_to_refresh` (626, 685); `installed_peers`, `peers_for_config`, `peer_for_policy` (945–1005) | `PathBudgets::probe` (652), which becomes `HostNet::route_mtu` |
| `Pending`, `stage_chunk`, `needs_authority_reset` (1009–1204); `validate_config` (3206) | `read_public_state`, `write_public_state*`, `validate_state_file` (715–912), which become the host's `NodeStore` |
| `WorkerCommand`, `Worker`, `PendingWorker`, `RuntimeState` (1218–1990): device build, `replace_peers`, admission | `PendingWorker::begin`'s inline calls to `configure_interface`, `dns::Resolver::bind`, `configure_host_dns` and `route(…"add")` (1319–1380), which become one `HostNet::apply` |
| `Node`'s state machine: `chunk` (2731), `up`/`ensure`, `down`, `counters`, rotation `prepare`/`commit`/`finish` (2483–3150) | `Node::restore` (2231): `macos_machine::bind`, `DnsIntegration::remove`, `Store::open_for_macos`, `macos_key::retire_key` |
| `RotationKey` (104), with `openssl::rand` (112) replaced by `ring::rand::SystemRandom` | `macos_key.rs`, `macos_machine.rs`, `macos_service.rs`, `macos_helper.rs`, `macos_user_mode.rs`, `macos_local_network.rs`, `macos_utun_ioctl.rs`, `macos_utun_holder.rs`, `macos_image.rs`, `dns_integration.rs` |

The Linux engine (`gotatun_node.rs`, `gotatun_tun.rs`, `node.rs`,
`wireguard.rs`, `netlink.rs`, `firewall*.rs`, `iptables.rs`, `seam.rs`,
`relay_path.rs`, `subnet_routes.rs`, `connection_state.rs`,
`proxy_access.rs`) stays in `plugins/mesh`. It is the only production user of
`new_multi_thread` (`gotatun_node.rs:760`). After the split it moves onto
`mesh-node`'s `engine` too, but that is not needed for iOS, so it comes last
or never. All coordinator modules (`api`, `store`, `settings`, `route_api`,
`node_coordination`, `rotation`, `presence`, `socket`, `descriptor`,
`diagnostics`, `configuration`'s compile side) stay server-only.

### The host traits

```rust
/// Everything the engine asks of the platform it runs on. The Linux and macOS
/// hosts implement it with today's netlink, ioctl and subprocess code. The iOS
/// extension implements it by handing one settings value to Swift, which
/// applies it with NEPacketTunnelNetworkSettings.
pub trait HostNet: Send {
    /// Apply the whole wanted interface state at once: addresses, the mesh
    /// route, subnet routes, the interface MTU and DNS match domains. Called
    /// after every applied chunk. It must be idempotent, because the engine
    /// re-sends the full state rather than a diff.
    fn apply(&mut self, wanted: &InterfacePlan) -> std::io::Result<()>;
    /// The path MTU towards one underlay endpoint, when the platform can
    /// tell. iOS returns `None`, and the engine then uses its safe default.
    fn route_mtu(&self, endpoint: std::net::IpAddr) -> Option<u16>;
}

/// Where the node keeps its public state and its private mesh key. Hosts
/// store them as root-owned files (Linux, macOS). iOS stores them in the app
/// group container and the shared keychain group.
pub trait NodeStore: Send {
    fn load_public(&self) -> std::io::Result<Option<Vec<u8>>>;
    fn store_public(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    fn load_private_key(&self) -> std::io::Result<Option<zeroize::Zeroizing<[u8; 32]>>>;
    fn store_private_key(&mut self, key: &zeroize::Zeroizing<[u8; 32]>) -> std::io::Result<()>;
}

/// Where packets come from: a utun file descriptor (the Mac hosts and the
/// extension's own utun), or a packet queue that Swift fills from
/// `NEPacketTunnelFlow`. The owner's answer (2026-11-24, item 5) is to
/// measure both on the iPhone and ship whichever is App Store-safe and faster.
pub enum PacketPath {
    Fd(std::os::fd::OwnedFd),
    Queue(PacketQueue),
}
```

### Dependencies and features

```toml
[dependencies]
infraternal-mesh = { path = "../infraternal-mesh" }      # policy types
infraternal-plugin-api = { path = "../infraternal-plugin-api", default-features = false }  # ActionDef, AgentPlugin, MAX_ACTION_BYTES; no socket-host
gotatun = { git = "…/gotatun", rev = "…", default-features = false, features = ["device", "ring"] }
ring.workspace = true                                     # randomness and SHA-256 (D289)
tokio = { version = "1", default-features = false, features = ["rt", "sync", "time", "net", "macros", "io-util"] }
nix = { version = "0.32", default-features = false, features = ["net", "ioctl", "poll", "uio"] }
zeroize.workspace = true
ipnetwork = "0.21.1"
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
hickory-proto = { workspace = true, optional = true }
tracing = { workspace = true, optional = true }

[features]
default = []
dns = ["dep:hickory-proto"]   # the mesh-dns feature of plugins/mesh forwards to this
tracing = ["dep:tracing"]
```

- GotaTun is gated to `cfg(unix)`, not to Linux and macOS.
- The `agent` feature of `plugins/mesh` keeps `tokio/rt-multi-thread`, but only
  through a `[target.'cfg(target_os = "linux")'.dependencies]` entry. Resolver
  3 then leaves it out of macOS and iOS builds.
- `infraternal-plugin-api` with no features needs only serde and serde_json. The grill's
  feature cut is therefore already in place. The `socket-host` (sqlx) and
  non-optional `sqlx` entries live in `plugins/mesh/Cargo.toml` and stay there.

---

## 2. `infraternal-link`: the client side of leg B

This crate dials the server, proves the identity and keeps the connection up.
It carries `Frame::Call`/`Frame::Result` (from `infraternal-protocol`) to an
`AgentPlugin`. The extension uses it for exactly one plugin, the mesh node.

### What moves

| Source | Into link | Stays where it is |
|---|---|---|
| `infraternal-agent/src/remote_supervisor.rs` | all of it: the retry loop, 200 ms→30 s backoff with jitter, offline watchdog, `LinkNotes` | |
| `infraternal-agent/src/remote_dial_runtime.rs` | all of it: the quinn `Runtime` wrapper | |
| `infraternal-agent/src/transport.rs` | `Receive`, `Transmit`: the bounded frame codec over `Channel` | `Socket`: the inherited leg-B fd through `infraternal_shim::readiness` |
| `infraternal-agent/src/remote_client.rs` | `dial_preferred`'s race, `quic_connect`, the Hello | `run_inner`'s uid check, machine binding, `plugin_control`, `sessions`, `daemon::*` dispatch, `host_os::client_info` |
| `infraternal-agent/src/remote_server_path.rs` | the path logic: `connect`, the Ping/Pong proof, mesh steering (`steer`, `candidate`, `to_enrolled`), `run_observed` | every parameter of type `plugin_control::Registry` becomes a small `LinkHost` trait (report the link, path preferences) |
| `plugins/remote/src/remote_quic.rs` | the client half: `client_config_with_liveness`, the transport settings (BBR, MTU), `peer_fingerprint` | `server_config` and `WebPkiClientVerifier` (server side) |
| `plugins/remote/src/enrollment.rs`, `agent_link.rs` | the wire models `JoinInvitation`, `JoinRequest`, `JoinResponse`, `AgentLinkChallenge`/`ProofV2`/`ReadyV2` and the v2 transcript functions | |
| `plugins/remote/src/server_leaf_floor.rs` | the logic and `ServerLeafStore`, over DER instead of OpenSSL `X509` | |
| `plugins/remote/src/wire_datagrams.rs` | `NativeDatagrams` (needed later, for app windows) | |
| `crates/infraternal/src/remote.rs` (join) | the CSR builder (over a `Signer`), `redeem`, the chain and key checks (`chains_to`), the invitation and origin checks (486–535) | `default_data`, the `prepare*` functions, pending keys, `publish`, `replace`, `migrate_identity`, `IdentityPublisher`, the uid checks |

What stays on OpenSSL, and therefore out of `link`, in the first steps:

- `remote_tls.rs`: the TCP/TLS fallback and the server acceptors.
- `remote_websocket.rs`: the 443 WebSocket fallback.
- `remote_renewal.rs`, `remote_recovery.rs`, `identity_rotation.rs`: their CSRs
  are signed with `MessageDigest::null()`, which only works for Ed25519.

The agent keeps using them. Until they are ported (PR L4 below), the iOS
link is QUIC only (Q1).

### The identity abstraction

Today `Identity { certificate: X509, key: PKey<Private> }`
(`remote_tls.rs:12`) reaches rustls through `private_key_to_pkcs8()`
(`remote_quic.rs:79`). A Secure Enclave key cannot be exported, so `link`
takes a signer instead:

```rust
/// The node's leg-B identity: its certificate chain, plus something that can
/// sign with the matching private key. Hosts load an Ed25519 PKCS#8 key from
/// their identity file (`Ed25519Pkcs8`). On iOS the extension passes a signer
/// that calls into Swift, where the key never leaves the Secure Enclave.
pub struct ClientIdentity {
    pub chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub signer: std::sync::Arc<dyn IdentitySigner>,
}

/// Signs with the identity key. `algorithm` decides the CSR and TLS
/// signature schemes: Ed25519 (hosts) or ECDSA P-256 with SHA-256 (iPhones).
pub trait IdentitySigner: Send + Sync + std::fmt::Debug {
    fn algorithm(&self) -> KeyAlgorithm;
    /// The SubjectPublicKeyInfo DER, which both the CSR and the key fingerprint use.
    fn public_key_spki(&self) -> Vec<u8>;
    /// Sign `message`. P-256 returns a DER ECDSA signature over SHA-256(message).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}
```

`link` adapts `IdentitySigner` to `rustls::sign::SigningKey`, so quinn's
`with_client_auth_cert` works without the private key bytes. The CSR builder
writes PKCS#10 DER by hand, as the inverse of the server's `csr.rs` envelope
parser, and signs it through the same trait (Q2).

### Dependencies and features

- `quinn` (`runtime-tokio`, `rustls-ring`), `rustls` (`std`, `ring`), `ring`,
  `tokio` (`rt`, `net`, `time`, `sync`, `macros`), `infraternal-protocol`,
  `infraternal-plugin-api` (no features), serde, serde_json, zeroize, uuid.
- `rustls-webpki` is already in `Cargo.lock` through rustls; it replaces the
  OpenSSL chain check (`chains_to`).
- Feature `join`: hyper (`client`, `http1`) over a rustls TLS stream, with
  the invitation's pinned root. It needs `tokio-rustls`, which is not in the
  tree (Q2).
- Feature `tls-fallback` (later): the TCP/TLS and WebSocket fallbacks on
  `tokio-rustls`.

---

## 3. `infraternal-sign-in`: device approval as a state machine

There are three copies of the wire types today:

- `crates/infraternal/src/sign_in.rs` (`DeviceStartRequest/Response`, `DeviceRedeemRequest/Response`, lines 560–584);
- `crates/infraternal/src/up.rs` (lines 283–298, its own `Approval`);
- the server's private `Deserialize` structs and `json!` replies (`auth/http.rs:129`, `auth/devices.rs:403`, `:651`).

This crate holds the one copy, plus the pure checks:

- `requested_scopes`, `server_url`, `approval_link`, `server_capability_has_shape`;
- `parse_redemption_response` and the status mapping (200 credential, 401 pending, 429 retry after);
- the machine-join start body (`up.rs:756` `machine_start_body`, `join_approval_link`).

**It does no I/O (Q3).** It builds requests and parses responses. The caller
moves the bytes:

- the CLI uses its existing hyper/OpenSSL `post_json` (`remote.rs:681`),
  unchanged;
- the app uses `URLSession`, which brings the system trust store, proxies and
  App Transport Security.

Credential files (`sign_in.rs:801–1040`), `HOSTNAME`, terminal output and
`run_flow` stay in the CLI.

Dependencies: serde, serde_json, url, zeroize. No tokio.

---

## 4. `infraternal-canvas-model`: the layout tree (later slice)

- `plugins/canvas/src/{model,reducer,tiling}.rs` move as they are. Their
  dependencies are serde, serde_json and uuid (only `Uuid::parse_str`,
  `model.rs:63`).
- `socket.rs` and `store.rs` stay in the canvas plugin, with `socket-host`.
- `examples/layout_oracle.rs` moves too. The tracer's differential test
  (`apps/tracer/src/canvas/model/reducer-property.test.ts:46–64`) changes
  `-p infraternal-plugin-canvas` to `-p infraternal-canvas-model`.
- The TypeScript model (`apps/tracer/src/canvas/model/`) does not move. D238
  keeps the web in TypeScript; the oracle test is the parity check.
- There are no canvas golden vectors yet; `contracts/vectors/` has `wire/`
  and `mesh/` only. Adding them belongs to the canvas slice.

The crate is not needed for slice 1. It is listed because its move is the
smallest one, and it proves the pattern (new crate, re-export, Nix vendoring,
doc-coverage baseline) at no risk.

---

## 5. What stays server-only or host-only

- **Server only:**
  - `infraternal-server`, `infraternal-db`, `infraternal-status`;
  - the coordinator half of `plugins/mesh`;
  - `plugins/{proxy,release,backup,host-facts,ssh}`;
  - the server side of `plugins/remote` (acceptors, `server_config`, `remote_accept`).
- **Host only:**
  - `infraternal-agent`'s plugin host, sessions and daemon;
  - `infraternal-shim`, `infraternal-session`, `infraternal-linux-tun`;
  - the platform modules of `plugins/mesh` (listed in §1);
  - `plugins/remote`'s `uninstall*`, `runtime_lock*`, `privilege_*`, `takeover_terminals*`, `inventory*`.
- **Later, not slice 1:**
  - the terminal state in `infraternal-shim` (`terminal.rs`, `terminal_native.rs`, libghostty-vt), which needs its own iOS build of the VT library;
  - the relay client (`plugins/relay`: `client.rs`, `probe.rs`, `tls.rs`).

---

## 6. The two FFI crates and the slice-1 Swift surface

Both crates are `crate-type = ["staticlib", "lib"]`. The `lib` type lets
their Rust tests run in `verify fast` on Linux. Both use UniFFI proc macros.
`infraternal-tunnel-ffi` also has a `cabi` module: the hand-written C
functions, with a cbindgen header.

### `infraternal-tunnel-ffi` (packet tunnel extension)

This crate depends on `mesh-node`, `link` and `infraternal-protocol` only,
and never on `sign-in` or `canvas-model`. One thread runs one current-thread
tokio runtime, as the macOS node does today (`macos_node.rs:1283`).

```rust
/// What the extension does for the Rust core. Swift implements this
/// (a UniFFI callback interface).
#[uniffi::export(with_foreign)]
pub trait TunnelHost: Send + Sync {
    /// Apply addresses, routes, MTU and DNS match domains through
    /// NEPacketTunnelProvider.setTunnelNetworkSettings. The engine's
    /// HostNet::apply calls this.
    async fn apply_network(&self, plan: NetworkPlan) -> Result<(), HostError>;
    /// Read or write one item in the shared keychain group
    /// (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly). The mesh key and
    /// the certificate chain live there.
    fn keychain_read(&self, item: KeychainItem) -> Result<Option<Vec<u8>>, HostError>;
    fn keychain_write(&self, item: KeychainItem, bytes: Vec<u8>) -> Result<(), HostError>;
    /// Sign with the Secure Enclave identity key (P-256). Returns a DER
    /// ECDSA signature over SHA-256(message).
    fn identity_sign(&self, message: Vec<u8>) -> Result<Vec<u8>, HostError>;
    /// The identity key's SubjectPublicKeyInfo DER.
    fn identity_public_key(&self) -> Result<Vec<u8>, HostError>;
    /// Public, already-redacted log lines for the unified log.
    fn log(&self, level: LogLevel, line: String);
}

#[derive(uniffi::Object)]
pub struct Tunnel { /* runtime thread, node, link */ }

#[uniffi::export]
impl Tunnel {
    /// Build the node from saved state. No packets flow and no link is dialled yet.
    #[uniffi::constructor]
    pub fn new(config: TunnelConfig, host: std::sync::Arc<dyn TunnelHost>) -> Result<std::sync::Arc<Self>, TunnelError>;
    /// mesh up: start the engine on the given packet path, dial the server
    /// and apply its configuration. Returns once the first network plan is
    /// applied, so startTunnel can call its completion handler.
    pub async fn start(&self, path: PacketSource) -> Result<(), TunnelError>;
    /// mesh down: close the link, stop the engine, keep the saved state.
    pub async fn stop(&self);
    /// mesh status: the same fields `infraternal mesh status --json` shows.
    pub fn status(&self) -> MeshStatus;
    /// A message from the app (NETunnelProviderSession.sendProviderMessage):
    /// one node action encoded as infraternal-protocol `Frame::Call`. The
    /// reply is a `Frame::Result`. Status, peers and routes reuse the node's
    /// action contract (D16), so no second schema exists.
    pub async fn app_message(&self, frame: Vec<u8>) -> Vec<u8>;
    /// The underlay changed (NWPathMonitor): restart the candidate walks.
    pub fn network_changed(&self, path: UnderlayPath);
    /// Enrolment step 1: generate the mesh key (it stays in the extension)
    /// and return what the approval needs: host id, key fingerprint.
    pub fn enrolment_begin(&self) -> Result<EnrolmentRequest, TunnelError>;
    /// Enrolment step 2: given the join invitation the app redeemed after
    /// approval, build a CSR signed in the Secure Enclave, POST /remote/join
    /// over the invitation's pinned root and store the certificate chain.
    pub async fn enrolment_finish(&self, invitation: String) -> Result<Enrolled, TunnelError>;
}

/// The utun fd found by the extension (Swift scans fds, ordinary syscalls),
/// or the packetFlow queue. Which one ships is measured in slice 1.
#[derive(uniffi::Enum)]
pub enum PacketSource { UtunFd { fd: i32 }, PacketFlow }
```

The C ABI exists only for the `PacketFlow` path, where every batch of packets
crosses the boundary. Swift owns the buffers and Rust borrows them, so a call
costs about 4 ns whatever its size (grill Q2):

```c
/* Packets from NEPacketTunnelFlow.readPackets, into the engine. */
int32_t itn_packets_in(ItnTunnel *t, const uint8_t *bytes, const uint32_t *lengths,
                       const uint8_t *families, uint32_t count);
/* Up to `max` packets for writePackets, copied into Swift's reusable buffer. */
int32_t itn_packets_out(ItnTunnel *t, uint8_t *bytes, uint32_t capacity,
                        uint32_t *lengths, uint8_t *families, uint32_t max);
/* Wake Swift when packets are waiting (it then calls itn_packets_out). */
void itn_set_wake(ItnTunnel *t, void (*wake)(void *ctx), void *ctx);
```

`ItnTunnel` is the same object as UniFFI's `Tunnel`. UniFFI hands its handle
to Swift, and `Tunnel::raw_handle` exposes it for these three calls.

### `infraternal-client-ffi` (the app)

```rust
/// Parse what the person typed into the server field: https only, origin only.
#[uniffi::export]
pub fn server_origin(input: String) -> Result<ServerOrigin, SignInError>;

/// The machine-join approval, driven by Swift with URLSession and
/// ASWebAuthenticationSession. No I/O happens in Rust.
#[derive(uniffi::Object)]
pub struct MachineJoin { /* the sign-in state machine */ }

#[uniffi::export]
impl MachineJoin {
    /// Start from the extension's EnrolmentRequest (forwarded as bytes).
    #[uniffi::constructor]
    pub fn new(server: ServerOrigin, device_name: String, request: Vec<u8>) -> Result<std::sync::Arc<Self>, SignInError>;
    /// POST /auth/device-start with kind "join_machine".
    pub fn start_request(&self) -> HttpRequest;
    /// Check the reply. Returns the approval URL for the web sheet and the expiry.
    pub fn on_start(&self, reply: HttpResponse) -> Result<Approval, SignInError>;
    /// POST /auth/device-redeem with `Prefer: wait=10`.
    pub fn redeem_request(&self) -> HttpRequest;
    /// Pending, retry after N seconds, or the join invitation to hand to the extension.
    pub fn on_redeem(&self, reply: HttpResponse) -> Result<Redeemed, SignInError>;
}

/// Encode one node action for sendProviderMessage, and decode its reply.
/// The status types (MeshStatus, Peer, Route) are shared with tunnel-ffi.
#[uniffi::export]
pub fn mesh_call(action: String, input_json: String) -> Vec<u8>;
#[uniffi::export]
pub fn mesh_reply(frame: Vec<u8>) -> Result<String, ProtocolError>;
```

Turning the mesh on and off from the app is Swift
(`NETunnelProviderManager`, `startVPNTunnel`/`stopVPNTunnel`). The app needs
no Rust for it.

### Enrolment, end to end (slice 1)

1. The app starts the tunnel with the option `enrol`. The extension applies a
   network plan with no routes and calls `enrolment_begin`, which generates
   the mesh key. The extension's Swift generates the Secure Enclave identity
   key in the shared access group.
2. The app receives the `EnrolmentRequest` through `app_message`.
   `MachineJoin` runs device-start, the server's approval page in
   `ASWebAuthenticationSession`, then device-redeem, and gets the join
   invitation.
3. The app sends the invitation to the extension. `enrolment_finish` sends
   the CSR to `/remote/join` and stores the chain. The extension then dials
   leg B and the node comes up.

This keeps the mesh key in one process, as the owner answered. The cost is a
brief VPN indicator during enrolment (Q5).

---

## 7. Server change: P-256 identity keys for iPhones

Today every identity is Ed25519. The checks that enforce that:

| File | What enforces Ed25519 | Change |
|---|---|---|
| `crates/infraternal-server/src/csr.rs:25–92` | `ValidatedCsr::parse` requires `Id::ED25519`. `validate_envelope`/`ed25519_algorithm` require OID `2b6570`, a 33-byte key and a 65-byte signature. | A second accepted shape: `id-ecPublicKey` + `prime256v1`, a 66-byte uncompressed point (`00 04 …`), `ecdsa-with-SHA256`, and a DER signature of up to 73 bytes in the BIT STRING. Same nesting, length and canonical-form rules. |
| `crates/infraternal-server/migrations/0015_remote_identity.sql:30` | `CHECK (length(public_key) = 32)` | A new migration (`scripts/new-migration identity_key_algorithm`): add `key_algorithm TEXT NOT NULL DEFAULT 'ed25519' CHECK (key_algorithm IN ('ed25519','p256'))`, and rebuild the table so the check becomes `(key_algorithm = 'ed25519' AND length(public_key) = 32) OR (key_algorithm = 'p256' AND length(public_key) = 65)`. |
| `enrollment.rs:33`, `ca.rs:216–220` | `CertificateRecord.public_key: [u8; 32]`; `host_key_digest` (enrollment.rs:233–260) | `public_key: IdentityKey` (an enum: `Ed25519([u8; 32])` or `P256([u8; 65])`). The digest is computed per variant. |
| `remote_enrollment.rs:72–76` | `raw_public_key()` then SHA-256, compared with `expected_key_digest` | Fingerprint per algorithm. Ed25519 keeps SHA-256 of the raw key, so existing invitations stay valid. P-256 uses SHA-256 of the 65-byte point. The client's digest (`remote.rs:365–392`) is defined the same way in `link`. |
| `auth/devices.rs:161` | `mode` must be `system` or `user`, tied to `execution_uid` | A third mode, `device`, with no uid. Only `device` joins may carry a P-256 key (Q4). |
| `remote_recovery.rs:46, 412, 619, 805, 878` | `MAX_SIGNATURE_BYTES = 64`, `public_key_from_raw_bytes(.., ED25519)`, `[u8; 32]` | Rebuild the key from `IdentityKey`. Verify P-256 with SHA-256, and allow up to 72-byte DER signatures. |
| `identity_rotation.rs:74–92, 237, 252, 729, 739` | `[u8; 32]` predecessor, `len() != 64`, `ED25519` | The same, per algorithm. An iPhone rotates by creating a new Secure Enclave key, which signs the CSR; the old key signs the handover. Nothing is exported (Q6). |

Already algorithm-neutral, so unchanged:

- QUIC mTLS: rustls `WebPkiClientVerifier` with ring accepts ECDSA P-256.
- Admission by the SHA-256 of the leaf DER (`remote_accept.rs:137, 339`).
- The CA signs subject keys of any type (`ca.rs:320`).
- The WebSocket proof's `verify_signature` (`remote_agent_http.rs:340–360`)
  already takes Ed25519 or P-256.
- The mesh `Enrolment.agent_key` is a hash of the key DER.
- The open branch `j1163-agent-challenge-tls-leaf` adds a v2 proof whose
  helpers accept both algorithms. Its TLS exporter is OpenSSL's; `link` would
  use rustls's `export_keying_material` when it ports that proof.

Tests use a software P-256 key (`ring::signature::EcdsaKeyPair`) in place of
the Secure Enclave. Each check gets a refusal test with mixed shapes: a P-256
key in a `system` join, an Ed25519 signature on a P-256 key, a long DER
length form, a compressed point.

---

## 8. Migration order: small PRs, each green on `verify fast`

Every PR moves code without changing behaviour, unless it says otherwise. The
old crate re-exports what moved (`pub use infraternal_mesh_node::dataplane;`),
so callers do not change in the same PR. Each new crate also needs:

- a workspace member entry and the `Cargo.lock` update;
- the Nix vendoring check (`Nix Cargo vendoring` row);
- a `scripts/doc-coverage-baseline.json` entry, since moved items keep their D345 comments;
- cargo-deny licences for new dependencies (UniFFI is MPL-2.0, as the grill notes).

**J1169** (`j1169-macos-route-client`) is changing `macos_node.rs`,
`macos_node/*`, `macos_helper.rs`, `macos_user_mode.rs`, `node_actions.rs`,
`subnet_routes.rs`, `walks.rs` and the mesh `lib.rs`. Steps 0–3 below touch
none of those files. Step 4 waits for J1169 to merge. Its first PRs touch
`lib.rs` only by one-line `pub use` edits, and leave `macos_node.rs` alone
until M5.

| # | PR | Touches | Gate beyond `verify fast` |
|---|---|---|---|
| **0. Prove the toolchain** | | | |
| T1 | Rust on std (Q7), then this page's Simulator check repeated on std for both targets, `aarch64-apple-ios` and `-ios-sim`. Add the iOS targets to the flake's dev shell next to `aarch64-apple-darwin`, not to `rust-toolchain.toml`, so `nix/package.nix` stays unchanged (`flake.nix:35`). | `flake.nix` | the check's log on #580 |
| T2 | GotaTun fork: put the `cdylib` behind a feature, so iOS static builds need no link (grill decision 12). Pin bump in `plugins/mesh`. | the fork; `crates/plugins/mesh/Cargo.toml` | GotaTun bench unchanged (#260) |
| T3 | `verify` row **iOS dependency guard**: `cargo tree --target aarch64-apple-ios -e normal,features` on the two FFI crates must not contain `openssl*`, `sqlx*`, `libsqlite3-sys`, `aws-lc*` or `tokio/rt-multi-thread`. It runs on Linux and needs no SDK. It lands with F1 (step 5), because the FFI crates have to exist first. | `scripts/verify.d/rust.sh` | the row fails on a planted `openssl` dependency |
| T4 | Measure whether the zig compiler wrapper that runs the macOS compile row (`scripts/verify.d/apple-check-cc`) can also type-check `aarch64-apple-ios-sim` from Linux. If it can, add an **iOS compile** row, so Linux gates catch iOS breakage without std. If it cannot, std's build is the only check. | measurement first | |
| **1. Canvas model (proves the pattern)** | | | |
| C1 | `infraternal-canvas-model`: move `model.rs`, `reducer.rs`, `tiling.rs`, `examples/layout_oracle.rs`. `plugins/canvas` re-exports them. The tracer test changes `-p`. | `crates/plugins/canvas`, new crate, tracer test | tracer unit suite (oracle test); the `canvas_layout_json` fuzz target still builds through the re-export |
| **2. Sign-in** | | | |
| S1 | `infraternal-sign-in`: the wire types and pure checks from `sign_in.rs`. The CLI uses them; its I/O is unchanged. | `crates/infraternal/src/sign_in.rs`, new crate | the existing sign-in tests |
| S2 | `up.rs` drops its duplicate types (283–298) and `machine_start_body`, and uses the crate. | `crates/infraternal/src/up.rs` | `verify-up-approval-namespace` |
| S3 | The server builds its device-start and redeem replies from the shared types instead of `json!`. A golden JSON test pins the bytes. | `crates/infraternal-server/src/auth/{http,devices}.rs` | auth browser suite |
| **3. Server P-256 (no client yet; each PR is reachable only from tests until P5)** | | | |
| P1 | `csr.rs` accepts the P-256 shape, with refusal tests. Nothing calls it with P-256 yet. | `csr.rs` | the `remote_csr_decode` fuzz target, with P-256 seeds added |
| P2 | `IdentityKey` type plus the migration: the `key_algorithm` column and the rebuilt check. Ed25519 rows are unchanged. | `enrollment.rs`, `ca.rs`, new migration | migration tests; restore from a pre-migration backup |
| P3 | Join and fingerprint per algorithm; mode `device`. | `remote_enrollment.rs`, `auth/devices.rs` | |
| P4 | Recovery and rotation per algorithm. | `remote_recovery.rs`, `identity_rotation.rs` | rotation tests with a P-256 software key |
| P5 | Turn it on: a `device` join with P-256 is admitted end to end, tested with a software P-256 client from `link` (L3). Server side (J1202): a `device` is a third host mode with no uid (`remote_hosts.execution_uid` is NULL exactly for it; migration `20261125055624_device_host_mode`). It joins, renews, rotates and is removed, appears in Mesh and the machine list marked as a device, and is refused everywhere a terminal, login or session list is decided. The test client signs with ring's P-256, not `link`. | small | the test server, when the orchestrator deploys it |
| **4. Link** | | | |
| L1 | `infraternal-link` with the pure parts: `remote_supervisor.rs`, `remote_dial_runtime.rs`, `transport.rs`'s `Receive`/`Transmit`, the `enrollment.rs`/`agent_link.rs` wire models, `wire_datagrams.rs`. The agent and `plugins/remote` re-export them. | `infraternal-agent`, `plugins/remote`, new crate | |
| L2 | `IdentitySigner` and `ClientIdentity`; the QUIC client config moves. The agent wraps its PKCS#8 Ed25519 key as `Ed25519Pkcs8`. `server_leaf_floor` works over DER. | `remote_quic.rs`, `remote_client.rs`, `server_leaf_floor.rs` | leg-B latency bench unchanged (D375 report) |
| L3 | The join client in `link`: CSR builder over `IdentitySigner`, `chains_to` on rustls-webpki, hyper over rustls with the pinned root. The CLI's join switches to it. Needs `tokio-rustls` (Q2). | `crates/infraternal/src/remote.rs` | `verify-up-approval-namespace`, real join on the test server |
| L4 | Later, not slice 1: the TCP/TLS and WebSocket fallbacks on rustls, then renewal and recovery. That removes OpenSSL from every client path (Q1). | `remote_tls.rs`, `remote_websocket.rs`, `remote_renewal.rs`, `remote_recovery.rs` | leg-B fallback tests, latency bench |
| **5. Mesh node (after J1169 merges)** | | | |
| M1 | `infraternal-mesh-node` with the as-is modules from §1: `dataplane`, `access_updates`, `candidates`, `candidate_walks`, `listen_port` (without `from_environment`), `underlay_announce`, `handshake_admission`, `packet_filter`, `tunnel_dns`, `peer_stats`, `dns_state`, `node_presentation`. `plugins/mesh` re-exports them. | mesh `lib.rs` (`pub use` lines), new crate | privileged integration (mesh rows), macOS compile |
| M2 | OpenSSL randomness and SHA-256 become ring in `enrolment.rs`, `macos_key.rs`, `RotationKey`, then `enrolment` moves. | 3 small edits | |
| M3 | Neutral halves of `mesh_mtu`, `dns`, `node_state` and `node_actions` (`parse_action`, `Request`, `ACTIONS`). | those 4 files | |
| M4 | Inside `plugins/mesh`, without moving anything: introduce `HostNet` and `NodeStore`, and route the macOS node's `route`, `configure_interface`, `PathBudgets::probe`, public-state and key-file calls through them. This is the risky edit, kept in one file at a time. | `macos_node.rs` | Mac VM proof: up, a route, rotation, down; the GotaTun bench on the Mac VM unchanged |
| M5 | Move the engine (`UtunTx`/`UtunRx`, `BoundUdpFactory`, `stage_chunk`, `Worker`, `RuntimeState`, `Node`'s state machine) into `mesh-node/engine`. `macos_node.rs` keeps only the host. | `macos_node.rs`, new modules | the same Mac VM proof and bench |
| M6 | `tokio/rt-multi-thread` only for Linux (target-specific dependency); GotaTun gated to `cfg(unix)`. | `crates/plugins/mesh/Cargo.toml` | release feature sets |
| **6. FFI and the first iOS build** | | | |
| F1 | `infraternal-tunnel-ffi` and `infraternal-client-ffi`, each exporting one call, plus T3's guard row. UniFFI and uniffi-bindgen are pinned in the workspace, as in the J1158 prototype. | new crates | iOS dependency guard |
| F2 | `scripts/ios/build-xcframework` (std, below), and the Simulator memory gate from grill Q3. | `scripts/ios/` | the run's log and the memory number on #580 |
| F3 onward | The slice-1 surface of §6, one call group per PR: status, start/stop, enrolment, app messages, the packet paths. | FFI crates | Simulator tests on std |

Steps 1–4 can run at the same time as each other. Within a step, the order
matters. Step 5 depends on J1169 merging and on L1 (the node needs the link's
`LinkHost` only when F3 wires them together, so M1–M6 do not wait for L2–L4).

---

## 9. Building the core for iOS on kayg@std

**Today (2026-11-24):**

- std has Xcode 27.2 (`27B52`), the iPhoneSimulator 27.2 SDK, 30 cores and
  326 GB free, but no Rust and no Nix.
- The Mac VMs cannot run Xcode (owner's correction on #580). Their Command
  Line Tools linker also rejects the iOS 27.2 SDK stubs (J1158).

**Pipeline on std** (`scripts/ios/build-xcframework`, run as `kayg` on std
under a new `/tmp/infraternal-std-ios-build.lock`; Simulator steps also take
`/tmp/infraternal-std-sim.lock`):

1. Use a Rust toolchain pinned to `rust-toolchain.toml`'s channel, plus
   `aarch64-apple-ios` and `aarch64-apple-ios-sim` (Q7). Put `CARGO_HOME`,
   `RUSTUP_HOME` and the target under `~/infraternal-ci/`, so nothing touches
   calternal or system files.
2. `cargo build --release --locked --target aarch64-apple-ios{,-sim} -p infraternal-tunnel-ffi -p infraternal-client-ffi`
   produces the static libraries.
   - C build scripts (ring) and the linker use `/usr/bin/clang` through a new
     `.cargo/apple-ios-cc.sh`. It is the iOS sibling of `.cargo/apple-cc.sh`
     and keeps `SDKROOT` from `xcrun --sdk iphoneos|iphonesimulator`.
   - `IPHONEOS_DEPLOYMENT_TARGET=26.0`.
   - The release profile uses fat LTO and one codegen unit, as the prototypes did.
3. `uniffi-bindgen generate --library` writes the Swift glue, and `cbindgen`
   writes `itn.h`.
4. `xcodebuild -create-xcframework` creates one XCFramework per FFI crate,
   with device and Simulator slices; no `lipo`.
5. `xcodebuild test` runs the Swift packages and the app on the
   `infraternal-01` Simulator. Then the memory gate runs: the extension's own
   `task_info` sample must stay under the 20 MiB budget.
6. The script writes sizes (stripped static library per crate), build times
   and the memory number to `~/.cache/codex-scratch/<job>/evidence/`.

**How it is triggered:** for now, an orchestrator job runs it over
`netbird ssh kayg@std.vpn.kayg.org`, like the Simulator QA today. A Forgejo
Actions runner on std (`.forgejo/workflows/` runs only the Linux `docker`
job) is a later choice for the owner; it is not needed for slice 1.

**What Linux gates cover without std:** the iOS dependency guard (T3), the
FFI crates' Rust tests (as `lib`), and, if T4 works, an iOS type-check.

---

## Open questions for the owner

| # | Question | Recommendation |
|---|---|---|
| Q1 | Slice 1's leg B on the iPhone: QUIC only, or port the TCP/TLS and WebSocket fallbacks to rustls first (L4)? | QUIC only for slice 1. The mesh itself is UDP, and relays run only on Linux today, so a network that blocks UDP stops the mesh anyway. Port the fallbacks (L4) before anyone else uses the app. |
| Q2 | New libraries (a library choice is the owner's): `tokio-rustls` for the join's pinned-root HTTPS (L3) and later the fallbacks; and whether the CSR is written by hand or with `rcgen`. | Add `tokio-rustls`, the rustls project's own tokio adapter (MIT or Apache-2.0). Write the PKCS#10 builder by hand (~150 lines, the inverse of the server's existing envelope parser, signed through `IdentitySigner`) rather than adding `rcgen`. |
| Q3 | Sign-in HTTP: Rust as a pure state machine with Swift's `URLSession` doing the I/O, or a Rust HTTP client in the app? | The state machine. The app then gets the system trust store, proxies and App Transport Security for free, there is no second HTTP/TLS stack in the app, and the CLI keeps its client. |
| Q4 | Which joins may use P-256: only the new `device` mode (iPhones), or any machine? | Only `device`. Linux and macOS paths stay Ed25519 and unchanged. Without App Attest the server cannot prove a key sits in a Secure Enclave, so this is a policy line, not a proof. |
| Q5 | Enrolment runs in the extension (started in an "enrol" mode with no routes), so the mesh key never enters the app process, as answered on #580. That shows the VPN indicator for a few seconds during enrolment. Acceptable? | Yes. The alternative, the app generating the mesh key, breaks the owner's "the extension generates the mesh key" answer. |
| Q6 | Do iPhone identities rotate like hosts' identities? | Yes, with the same protocol: a new Secure Enclave key signs the CSR, the old key signs the handover, nothing is exported. |
| Q7 | Rust on std: a user-level rustup under `~/infraternal-ci/`, pinned to `rust-toolchain.toml`, or Nix on std (a multi-user install creates a system volume on the owner's Mac)? | User-level rustup. It needs no system files, and Xcode stays the only Apple toolchain. Nix keeps pinning the Linux and Mac VM builds. |
| Q8 | Slice 1 does only the machine join, with no API credential (device-start with `kind: "sign_in"`) in the app. The app reads status from the extension. The API credential comes with the canvas slice. OK? | Yes. It keeps a second secret and its keychain item out of slice 1. |

## Not answered here

- The iPhone numbers: extension memory with the link, both packet paths,
  UDP buffer accounting (grill Q3).
- Whether Secure Enclave keys in a shared access group sign from the
  extension on a real device. Apple staff call it "reasonable", not
  guaranteed (grill Q4).
- T4: whether zig can type-check the iOS targets from Linux.
