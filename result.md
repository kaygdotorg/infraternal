<!-- Records the production integration of #151 and #158 under D206, including reproducible gate evidence. -->

Merged `origin/session-bounds` into the production line: merge `026e471c`, fixture follow-up `f2d84235`. The shim’s authenticated saved exit uses `terminal.exited` with status, then the sole final Close 4404. Retired status preserves viewer cursors; live exits retain final-output paint ordering. Both branches’ tests remain; the native completion/drain and interrupted-answer races have regressions.

Validation: **601 Rust tests passed**, 0 failed, 63 ignored; SB-01 and DS-01..DS-04 pass. Tracer check and **142 src tests**, **36 protocol tests**, **7 production browser tests**, and **7 real-PTY switching tests** pass. Native final-response regressions: **5 passed in 1.05 s**. No load failure was waived.

Three default builds: deferred Brotli **44,773 / 44,705 / 44,734 B**, below unchanged **45,056 B** (D188). Final static x86_64 binary: **19,992,480 B**, versus exact `b373cc4c` **19,904,832 B** (**+87,648 B**); no PT_INTERP. The known **16,404,816 B** limit remains unchanged.

`scripts/verify fast` summary, verbatim:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```

Scale on infraternal-dev, 8 CPUs, CPUWeight=10000, real 80×24 PTYs: **200 recovered / 201 admitted / 200 after reap**. Combined PSS: **341,851 KiB empty** (1,709.26 KiB/session × 200), **3,710,906 KiB filled** (18,554.53 KiB/session × 200); 200 independent owners add no measured PSS. Facts 101 samples: p50 **4.589 ms**, max **44.399 ms**. Load 25.68/27.04/25.28 → 33.93/28.81/25.88.

Separate 200 sequential final replies: p50 **232 µs**, p99 **700 µs**, max **1,912 µs**, load 46.25/36.84/29.80. Production captures, read-only reviewed: [exit 0](apps/tracer/captures/dead-session/retired-exit-0-1440x900-ink.png), [exit 7](apps/tracer/captures/dead-session/retired-exit-7-1440x900-ink.png).

Author checklist and raw findings: [#151](https://git.kayg.org/kayg/infraternal/issues/151), [#158](https://git.kayg.org/kayg/infraternal/issues/158). Logs and binary evidence remain under `$HOME/.cache/codex-scratch/session-bounds-prod/`; temporary targets/checkouts are removed.
