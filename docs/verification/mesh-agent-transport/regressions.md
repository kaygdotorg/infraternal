<!-- Failed-before-fix evidence for restored decoder and capability regressions, issue #129. -->

# Regression provenance


## resume-tcp-red2.log


```text
---- remote_client::tests::proven_tcp_decoder_preserves_mux_envelopes_and_buffered_suffix stdout ----

thread 'remote_client::tests::proven_tcp_decoder_preserves_mux_envelopes_and_buffered_suffix' (166884) panicked at crates/infraternal-agent/src/remote_client_tests.rs:569:47:
called `Result::unwrap()` on an `Err` value: Custom { kind: InvalidData, error: UnknownType(12) }
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 64 filtered out; finished in 0.05s
```


## resume-capability-red.log


```text
---- remote_client::tests::server_path_capability_is_advertised_on_native_and_fallback_transports stdout ----

thread 'remote_client::tests::server_path_capability_is_advertised_on_native_and_fallback_transports' (368503) panicked at crates/infraternal-agent/src/remote_client_tests.rs:642:9:
assertion `left != right` failed
  left: 0
 right: 0
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 66 filtered out; finished in 0.20s
```
