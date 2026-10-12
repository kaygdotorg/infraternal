# Native secondary review, #129 / D215

The initial server draft passed `cargo check --locked -p infraternal-server --features remote --lib` in 40.49 seconds. The incremental/marker draft passed the same check in 9.55 seconds with one unused-mut warning, subsequently removed. These are typechecks, not behavioral acceptance.

The original real-mTLS primed admission regression failed with ApplicationClosed (0 passed, 1 failed, 0.29 seconds). The revised regression also opens an actor writer after parking and requires a matching native bound stream whose first two frames are `transport.prime {}` and AttachTerm. It preserves the host generation until activation.

Review found that connection-wide priming mode could change while an incremental bind was in flight. The agreed contract now carries explicit per-bound-stream intent before AttachTerm. Server promotion aborts and joins its setup task before releasing the priming state. Negotiated host capability, rather than current parking state, controls marker acceptance.

The server draft keeps one bounded secondary and at most 128 slot records. Incremental setup owns a single cancellable task, caches first Ack without acknowledging browser input, and leaves refused or expired writers on the ordinary path. Retained input lives only in AttachmentState; shadow metadata holds acknowledged/sent cursors, credit and readiness. Later hedges send new retained suffixes rather than repeating the first payload. Output overlap is trimmed before actor/browser credit accounting. Stale snapshots become empty output no-ops; valid newer snapshots retain their ordinary validation.

Open acceptance work: real incremental/promotion tests; queued native frames from a retired channel must not affect a replacement channel with the same writer id; indivisible snapshots larger than the first16KiB credit grant need an explicit bounded follow-up grant policy; exact production standby/activation parser ASAN sampling; full Clippy and repository gates. The actor's existing awaited active write can delay the 200ms hedge under write saturation; no general RTT+250ms claim is made from this draft.
