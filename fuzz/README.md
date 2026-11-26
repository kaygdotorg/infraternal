<!-- Reproducible parser fuzzing: host facts, shim framing and the wire codec [12][40]. -->
# Fuzzing

The bounded host-facts request decoder and OS release parser, shim framing,
and wire codec have fuzz targets in this one harness crate.

## Desktop source action JSON

`desktop_source_json` calls the same pure typed decoder as `SourceBridge.execute`,
before any authority, helper process, runtime directory or native capture work.
The selector byte chooses a declared source action. Accepted requests must obey
the frozen 8 KiB action limit, survive canonical JSON encoding, and reject added
foreign fields. Seeds cover all action shapes, duplicate fields, positional
arrays, and both sides of the size boundary. Deterministic tests additionally
check invalid source UUIDs, target identities and geometry.

```sh
python3 fuzz/seed.py --desktop-source-only target/desktop-source-corpus
CARGO_PROFILE_RELEASE_LTO=false cargo +nightly fuzz run desktop_source_json \
  target/desktop-source-corpus -- \
  -max_total_time=60 -max_len=16384 -rss_limit_mb=2048
```

This target does not substitute for the real mTLS QUIC Source integration tests
or macOS capture/input/restoration measurements.

## Host facts

The host-facts target exercises strict read/configure JSON decoding, the
bounded `/etc/os-release` and `/proc/loadavg` parsers, and the fixed-size
macOS load-average sysctl decoder. It performs no host reads while fuzzing.

```sh
cargo +nightly fuzz run host_facts_decode -- -max_total_time=600 -max_len=16384
```
Both parsers of untrusted bytes have fuzz targets in this one harness crate.
The production Mesh action parser also has a target for its JSON boundary.

## Shim framing

Run from the repository root:

```sh
CARGO_PROFILE_RELEASE_LTO=false cargo +nightly fuzz run shim_frame_decode \
  fuzz/corpus/shim_frame_decode -- \
  -max_total_time=610 -max_len=1048580 -rss_limit_mb=2048
```

LTO is disabled only for fuzzing: LLVM coverage instrumentation and workspace
release LTO produced undefined `__sancov_gen_` symbols on the tested nightly.
Production retains workspace LTO. The harness tests type/payload decoding,
canonical re-encoding, and fragmented/coalesced length-prefixed streams.
Golden seeds include every frozen v1 frame both with and without its prefix;
other seeds exercise malformed lengths. Generated corpus entries can be saved
under `target/` after a run. Ordinary fast tests also check the exact 1 MiB limit.

## Wire codec


Run `python3 fuzz/seed.py` from the repository root to seed every golden type,
all mux-id widths and the short-frame data-loss regressions. Then run:

```sh
cargo +nightly fuzz run wire_frame_decode -- -max_total_time=600 -max_len=65536
cargo +nightly fuzz run wire_stream_decode -- -max_total_time=600 -max_len=65536
```

The direct target checks raw and mux round trips. The stream target compares
frame order, bytes, terminal errors and retained incomplete bytes against direct
decoding, with input-selected tiny/large chunks and empty feeds. It also creates
valid Close/Credit/Output concatenations. Missing callbacks fail assertions.
The deterministic cross-runtime test compares scalar fields, payloads and
re-encoding across every two-chunk split and seeded random multi-splits.
Maximum 4 MiB frames are deterministic tests, avoiding that cost on every fuzz
iteration. Execution/edge counts are evidence, not source-coverage percentages
or connection-layer authorization tests.

## Mesh action JSON

Run from the repository root to seed all 16 public Mesh actions, including an
explicit null port policy, and fuzz the same `parse_action` function used before
server-side SQLite work:

```sh
python3 fuzz/seed.py --mesh-only
CARGO_PROFILE_RELEASE_LTO=false cargo +nightly fuzz run mesh_api_json -- \
  -max_total_time=60 -max_len=65536 -rss_limit_mb=2048
```

The first input byte selects an action; remaining bytes are its JSON input.
The target checks parser robustness and validation boundaries, not database
authorization or transaction behavior. The JSON shapes and action IDs are
specified in contracts/mesh-api.md.

## Relay frames

This target includes the production relay wire codec directly, so it exercises
the same fixed-size request and notice decoders, host-ID parser and DATAGRAM
header parser without enabling the relay runtime or pulling it into the
shipping feature set. It checks round trips for every accepted frame and
returns normally for arbitrary bytes up to 4 KiB.

```sh
python3 fuzz/seed.py --relay-only
CARGO_PROFILE_RELEASE_LTO=false cargo +nightly fuzz run relay_wire_decode -- \
  -max_total_time=60 -max_len=4096 -rss_limit_mb=512
```

The synthetic corpus includes each control kind, a zero link ID, truncated and
overlong frames, a DATAGRAM header, and a valid enrollment URI. It contains no
credentials or captured network data.

## Auth capability cookies

`auth_cookie` includes the production capability reader source. It feeds up to
64 split fields, checks canonical 43-character values and asserts that a matching
duplicate in any additional field is denied for both session and ceremony names.
Inputs rejected by HeaderValue construction do not reach the cookie layer.
Use a scratch target/corpus and the repository Zig/make/perl environment:

```sh
CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/auth-cookie/target" \
  CARGO_PROFILE_RELEASE_LTO=false cargo +nightly fuzz run auth_cookie \
  "$HOME/.cache/codex-scratch/auth-cookie/corpus" -- \
  -max_total_time=60 -max_len=4096 -rss_limit_mb=512
```

The #149 instrumented run completed 1,781,320 inputs in 61 seconds without a
crash. Native/proxy TLS evidence and parser cost at 50 sessions are recorded in
`docs/verification/tls-session.md`. Corpus seeds must be synthetic test values;
never capture real browser cookies.

## Campaign targets of 2026-11-21 (#561)

Six parsers of untrusted bytes had no target until #561. Each one now calls
the production code through a `parser-checks` (or, for the vendored SSH
engine, `fuzz-hooks`) entry point that only this crate enables. Their
synthetic seeds come from `python3 fuzz/seed_campaign.py` and are committed
under `fuzz/corpus/<target>/`. Each hook's unit test replays them, so
`cargo test` runs every entry point on the stable toolchain (ENGINEERING P5).

| Target | What it checks |
|---|---|
| `terminal_stream_receive` | Browser WebSocket messages → mux frames (`receive_wire`): whole frames in order, buffer cap, Text/Close handling, at most one unfinished frame at the end; terminal-open bodies |
| `agent_control_messages` | Local control-socket framing (`read_one`) in any read sizes, `sessions.*` argument checks, saved session names, CLI reply round trip, the Hello `os=` token |
| `desktop_reassembly` | Video fragment reassembly under loss, repeats, reordering, foreign sessions and deadlines |
| `remote_join_approval` | `/remote/join` body and canonical CSR, owner-approved `JoinMachineRequest`, receipt token, canonical invitation secret, invitation and link-challenge JSON |
| `vt_stream_snapshot` | PTY output in any pieces gives the same snapshot; snapshots fit a frame; a snapshot continues the stream. A continuation failure is labelled `CARRY-CLASS` (cutting the carry off the snapshot makes it pass: the carry observer is at fault) or `REPAINT-CLASS` (the repaint itself) |
| `ssh_packet_read` | The SSH packet reader with its 256-byte read-ahead (#538): sealed packets survive a key change; hostile bytes end in an error without consuming a sequence number |

The J1261 round-two target `mesh_coordination_json` covers authenticated node
replies for LAN candidates, subnet routes, IPv6 state and side-socket state,
including the reply-byte and collection-count limits. Its inputs need no
feature flags or captured peer data.

Build hosts without a nightly toolchain can run them with the pinned stable
compiler from the dev shell and cargo-fuzz from nixpkgs. `RUSTC_BOOTSTRAP=1`
lets stable accept the coverage flags, and no sanitizer is needed for these
memory-safe harnesses. `-a` turns on debug assertions, so arithmetic
overflow panics:

```sh
fuzz_bin="$(nix build --inputs-from . --no-link --print-out-paths nixpkgs#cargo-fuzz)/bin"
nix develop -c env PATH="$fuzz_bin:$PATH" RUSTC_BOOTSTRAP=1 CARGO_PROFILE_RELEASE_LTO=false \
  cargo fuzz run -s none -a --features mesh-node vt_stream_snapshot fuzz/corpus/vt_stream_snapshot -- \
  -max_total_time=600 -max_len=65536 -rss_limit_mb=2048
```

## Host and device CSRs

`remote_csr_decode` runs every input through both admitted request shapes:
`ValidatedCsr::parse` (the Ed25519 host shape) and
`ValidatedCsr::parse_as(.., KeyAlgorithm::P256)` (the P-256 device shape,
#580). No input may pass as both. The checked-in seeds in
`fuzz/corpus/remote_csr_decode` come from `python3 -I fuzz/seed_csr.py`, which
makes throwaway keys with `openssl req` and signs with `openssl dgst`. They
are: `ed25519-host` (Ed25519 host request), `p256-device` (admitted P-256),
`p256-high-s` (admitted; S above n/2 as a Secure Enclave can produce),
`p256-compressed-point`, `p256-explicit-params` (refused by the envelope), and
`p256-truncated` (refused: cut short). The script rebuilds these on demand and
checks them with `openssl req -verify`. Its keys are temporary and never
committed.

```sh
python3 -I fuzz/seed_csr.py
CARGO_PROFILE_RELEASE_LTO=false cargo +nightly fuzz run remote_csr_decode \
  fuzz/corpus/remote_csr_decode -- -max_total_time=600 -max_len=4200
```
