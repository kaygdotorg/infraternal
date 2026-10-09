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
