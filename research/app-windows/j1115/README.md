<!-- Role: how to rerun the J1115 App Windows encoder-mode and sharp-refresh measurements (#146). -->
# J1115 encoder mode and sharp refresh probes

Measurement harnesses for J1115 on #146. They are not product code. The results
are in the J1115 comments on #146.

## One command for any Mac

```sh
research/app-windows/j1115/run-encoder-probes.sh          # full run
research/app-windows/j1115/run-encoder-probes.sh --quick  # fewer sizes and frames
```

It builds the J1078 encode probe (`../j1078/encode-probe`) and the J1115
encoder-mode probe with the Mac's own `swiftc`, runs the sections that decide
the encoder mode, and writes `encoder-probes-<model>-<time>.log` in the current
folder. It installs nothing and changes no setting. Attach the log to #146.

## encoder-mode-probe

Builds the session of `crates/plugins/desktop/native/Encoder.swift` in the
low-latency mode (`lowlat`, before J1115) and in the ordinary real-time mode
(`realtime`), with and without `DataRateLimits` caps, and measures:

- `mode`: steady 120 and 60 Hz typing and scrolling at 0.28, 1.56 and 4.1 MP:
  encode p50/p95/p99, dropped frames, kbit/s against the budget, the largest
  frame, and the PSNR of what the viewer is shown;
- `sparse`: one typed change after a 50 ms to 2 s gap;
- `refine`: after a 250 ms pause, the forced keyframe at 4x against up to 8
  delta passes at 2x or 4x, scored pass by pass, after typing, after
  scrolling, and after a lone motion-budget keyframe (`static`: startup,
  resize, repair).

`ONLY=mode,refine` picks sections; `ARMS=lowlat,realtime` picks arms; `QUICK=1`
shortens it.
