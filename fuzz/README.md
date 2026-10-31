<!-- Reproducible parser fuzzing: host facts, shim framing and the wire codec [12][40]. -->
# Fuzzing

The bounded host-facts request decoder and OS release parser, shim framing,
and wire codec have fuzz targets in this one harness crate.

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
