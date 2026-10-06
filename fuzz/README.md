<!-- Reproducible parser fuzzing instructions and seed provenance [12][40]. -->
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
