<!-- Independent D74 handover review findings, J848, issue #521. -->
# D74 size handover review

Verdict: **FIX**. Reviewed implementation from `f9d8bcf11`, including J837's
ownership tests, merged with dev `6a88ce439`.

## P2: EOF and Resize in one readiness batch lose the handover

With two attached writers, let writer 0 own 80×24. Close its socket and queue
writer 1's Resize to 60×20. When both events are ready, the reactor reads the
owner's EOF first, but leaves `active_writer` set while it dispatches the next
peer's Resize. That report is staged. Only after dispatch does it remove the
departed peer and clear ownership. The session stays at 80×24 until another
Resize or new input, contrary to the amended D74.

The committed regression uses real socket pairs and a real PTY through
`Session::step`, with explicit `[POLLHUP, POLLIN]` readiness. It has no sleep
or timing assertion. Run it with:

```sh
cargo test -p infraternal-shim --lib --features process-per-user \
  departed_typist_eof_precedes_resize_in_the_same_poll_batch -- --nocapture
```

The assertion observes `(80, 24)` instead of `(60, 20)`. The same ordering is
present in the per-session shim's ready-peer loop. Settle observed departures
before later size reports in both modes, while preserving an already attached
replacement or shared link of the owning writer. Add the real-dispatch
regression to the author fix; extending a wait does not fix this case.

This review intentionally retains the failing regression, as PROCESS §9
requires. It makes no product fix. Forgejo #521 holds the raw receipts and
exact-head gate output; local evidence is outside the checkout under
`~/.cache/codex-scratch/j848/evidence/`.

## Other reviewed rules

The attached-owner, returning-typist, two reopen orders, requested versus
accepted size, and same-size raw replay controls pass in both shim modes.
Five mutations fail behavioral assertions: suppress ownership release (10
failures), ignore attachment state (1), steal the attached owner's size (6),
accept staged geometry (2), and suppress the reconnect repaint (15).

The writer-size probe fix forces replay from cursor 0 and asserts the intended
Snapshot and notice. It adds no wait. J820/J833's retained red and timing
receipts are on #521; their shared-host timings are observations rather than
a pinned performance qualification.
