<!-- Records the #158/D206 round-two fixes, verification evidence and remaining gate exception. -->

Round two addresses all four HOLD findings. Code head: `fbc28c18`.

- DS-03: `d215b3c0` drains queued native final frames before retirement, bounded to one second. `cbabf63e` adds the stuck-peer regression; `3b55079c` fixes its documentation lint.
- DS-01: `003126ad` keeps known gone inventory records exited when another window selects them.
- DS-04: `be84bd8f` shares the existing jittered retry policy; `14f0fdca` retries transient shared-stream closes on the same durable writer. `16dc989c` and `fbc28c18` prove stream identity and acknowledged input continuity.
- DS-02: retained a552bb2e's on-demand logs body. Five fresh default production builds: **44,704 / 44,708 / 44,720 / 44,709 / 44,679 B** deferred Brotli, each below the unchanged **45,056 B** limit.

Imported review tests: `445d4abb`, `48b07c5d`, `796b4f11`, `add06701`, `8cac789a`. Assertions were preserved; inventory, native and transient-browser failures were reproduced before their fixes.

`scripts/verify fast` summary:

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

The sole remaining failure is the known static-size overrun: **19,904,800 B**, versus an exact a552bb2e baseline of **19,904,384 B** (**+416 B**); maximum remains 16,404,816 B. No failed test was waived. GNU checks reused this job's locked vendored OpenSSL archive; the static build used the default musl recipe.

TypeScript fast passed separately because the static failure stops the combined dispatcher. Tracer check and src tests: **122 passed, 0 failed, 10,862 assertions**. Protocol tests: **36 passed, 34,462 assertions**. Production browser specs on 5791/5792: **4 passed in 58.5 s** (dead-session, detached-output, both transient retry specs). Real QUIC final-close and stuck-peer tests passed.

The isolated real-channel diagnostic preserved all **200 sequential vanished-session replies**, including late Input/Close/Ping fences: **p50 210 µs / p99 4,526 µs / max 4,777 µs**. Local infraternal-dev, eight CPUs, CPUWeight=10000; initial/final load averages **8.14 / 13.87 / 21.11**. This measures sequential refusals, not 200 live PTYs.

Production screenshot: [ended terminal](apps/tracer/captures/dead-session/ended-1440x900-ink.png). Author checklist and raw findings are recorded on [#158](https://git.kayg.org/kayg/infraternal/issues/158); it remains open. Logs and baseline/final binary artifacts are retained under `$HOME/.cache/codex-scratch/fix-dead-session-round2/`; build targets and temporary source checkouts are removed after verification.
