<!-- Role: reproduce the isolated owner app-window test without changing production (#146, D208, D309). -->
# Try app windows

This is an experimental preview. The latency target and a clean ten-minute
stability check have not passed.

From the build-host worktree, run:

```sh
PATH=/home/kayg/.nix-profile/bin:$PATH scripts/app-window-owner-preview /home/kayg/.cache/codex-scratch/app-windows-latency-r3b/bin/infraternal-desktop
```

The launcher waits for the physical MacBook lock and an idle guest VM, checks
battery and existing capture permissions, starts a desktop-enabled server on
`10.69.69.125:4347`, and opens a separate browser on the MacBook. Its authenticated
canvas uses an isolated test account and fresh server state. It does not use the
production account or install a companion. The browser maps its own `localhost`
address to that preview; use the opened browser, rather than a production tab.
The signed companion opens as its own app. Existing permission checks must pass;
if a permission prompt appears, capture is denied, or no first frame arrives
within ten seconds, the run stops. It never approves a prompt or retries capture.

Keep the MacBook awake and unlocked. Wait for `owner_preview_ready` in the
terminal. The coloured “App window measurement” window is ours and safe to type
into directly; watch its streamed picture update in the browser. Resize the
canvas picture, close its canvas window, and reopen it using **New window** →
**App window measurement**. The fixture has a fixed native size, so it fits inside
the available picture. Other open app windows appear in that same picker. Only
choose your own non-sensitive test content; the preview relays the selected
window through the build host.

To watch a repeatable full remote-input typing and resize check, add `--demo` to
the command. It drives only the fixture, records the isolated canvas, and exits
after cleanup. Leave the Mac's physical mouse and keyboard idle during that run.

Local mouse or keyboard use on the Mac pauses remote input for two seconds.
This also applies when the viewer is on the source Mac: physical typing in that
viewer yields to local input. The automated demo exercises the full remote-input
route without overriding this protection.
A window controlled by a desktop window manager retains its native size. The indicator on the Mac identifies remote
control. Closing the stream releases held input and restores any size it changed.

Close the test browser to finish. Each run has a hard 15-minute deadline, with
the final 30 seconds reserved for cleanup. The owner launcher also stops its
browser after 15 minutes. It removes its private server state and stops its
browser, fixture window, source process and helper children.
No production service, owner fixture, permission entry or trust setting changes.

## Known limits

- The recorded fixture can show clipped text or a black band while
  its native size changes under the desktop window manager. Resize is part of
  the checklist, rather than a claim of finished picture geometry.
- The ten-minute rehearsal also found occasional slow updates and native child
  exits that need attribution. It did not qualify as a clean stability pass.
  The first typing burst after the connection drop was lost, and some child
  retirements had unclassified causes. A browser regression now verifies that
  pending typing drains after automatic control reacquisition; it does not
  replace a repeated soak. Close/reopen succeeded after the closing-record fix.
  The new launch path has a separate functional check;
  see [#146](https://git.kayg.org/kayg/infraternal/issues/146) for the recorded
  counts, timings and current validation limits.
- This is the relayed path. The direct path is separate work after D309's latency
  work; network travel remains visible while typing.
- The previous measured added latency exceeded the 16 ms target. A responsive
  test does not establish that target or physical input-to-photon latency.
- Idle pictures stop, but capture still uses CPU. Near-zero idle source CPU and
  full-rate motion are not established.
- The automated reconnect check drops the preview browser connection. Losing
  the Mac's whole network connection or restarting it is not covered by that check.
- One source is the tested setup. Multiple sources and viewers at scale remain
  unproved; the retained comparison history alone can use 16 MiB per source.
- This test uses the supported hardware-accelerated browser on the physical
  MacBook. It does not establish browser parity or phone quality.
