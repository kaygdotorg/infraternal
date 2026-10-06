<!-- Documents reproducible codec fuzzing and the stream-equivalence oracle. -->
# Wire codec fuzzing [12][40]

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
