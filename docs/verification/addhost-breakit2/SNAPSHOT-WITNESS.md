<!-- Explains the real-engine output witness regression and its exact paint/ack boundaries (#189). -->

# Add-host painted output witness

A Snapshot contains a positioned repaint. Visible rows use absolute cursor
movement; its byte program does not reproduce the PTY's original CRLF stream.
The timeline therefore reads complete rows with the existing
`TerminalClient.readScreenText()` only from `onPaintedOutput`. Polling observes
the saved painted-row result and cannot accept parsed output before paint.
Both complete marker rows must remain present when all 59 input bytes are
acknowledged. The installed full-image SHA-256 proof is unchanged.

`snapshot-witness.c` emits a real repaint from the pinned native engine. Build
it with the completed GNU native archive and include directory using the same
`zig cc` arguments as `scripts/verify-vt-native.py`; keep its executable and
stdout under the job cache. Set `ADDHOST_WITNESS_SNAPSHOT` to that stdout file.
Run `snapshot-witness.mjs` with a unique `TRACER_TEST_PORT`. It loads that
repaint into the shipping browser renderer, waits for paint and calls the
shipping screen reader. A faithful repaint must pass; corrupted and extended
marker rows must fail. It prints only fixed case names and booleans.

`ADDHOST_WITNESS_MODE=raw` selects the original CRLF predicate as a negative
control. It must fail despite both rendered rows being correct. This proves
the representation mismatch independently of an earlier live timeout; that
failed live attempt remains recorded. Timeline refusals also retain fixed
marker flags and input cursor counts, without terminal contents or authority.
