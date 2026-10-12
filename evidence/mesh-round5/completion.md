<!-- Round-five review repair and full verification handoff for #173, D242/D243. -->
# Round 5 handoff

All independent regression cases pass without altered assertions. The earlier MPVR-1/2/3 repairs are retained; both MPVR-4 frontends require an initiating SYN before fresh TCP acceptance. Exact tuple/ID/zone retirement removes original and reply indexes without removing permitted state. Atomic source checkpoints are documented in `correctness.md`.

Fresh resumed verification: 16/16 named kernel cases, fresh-store withdrawal 1/1, production EnrollmentStore withdrawal 1/1. Earlier exact-state proofs retain 344/344 assertions, journal rollback 8/8 and saved-intent recovery 20/20. The six reviewer/helper files match their original commits byte for byte. Author checklist: `reviewer-checklist.md`.

Locked authorized-VM campaign: 24/24 coordinator changes plus 32/32 apply cohorts. Both orders and all samples are retained. Combined median shifts are −1.43% to +0.83%; reverse ordering does not reproduce the first campaign's larger positive shifts. No exact-zero-cost or tail improvement claim. The 1,000-peer/150 ms default-tightening delivery remains approximately six seconds. Three live nodes/two receivers with 10/1,000 installed kernel peers are distinct from 1,000 live workers. See `performance.md`, full distributions in `performance-summary.json`, and the two checksum-recorded archives (extract their contents under an evidence directory to inspect raw files).

Complete `scripts/verify fast` at pushed source/evidence head `3fe3a0b3` uses the recorded native qualification and VM-only RTT setup. All test rows pass; the earlier unchanged shipping shim case passes in the complete run. Its first failed attempt and isolated success remain in `resume-fast.log` and are not used as a waiver. The sole failed final row is the unchanged D243 ceiling. Static x86_64: 22,408,144 bytes, PT_INTERP absent, ceiling 16,404,816 bytes. ARM qualification and the subsequent TypeScript stage are not reached after that size failure. No TypeScript is changed in this round. Integration remains held for the owner's size-reduction work; no decision or threshold is changed.

Full run: 956 passed, 0 failed, 128 ignored across 104 successful result rows, including CLI compile-out. Complete stdout/stderr: `final-head-fast.log` (SHA256 `5711855e7027b27bc1c968eb500db17e52f3580e9386a341afcbb7af03daa527`). Evidence-only completion commits do not alter production/test sources. The final named-head check is also retained on the issue before handoff.

Final recorded summary, verbatim:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| CLI plugin compile-out    | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```

No deployment or issue closure.
