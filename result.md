<!-- Records #149 production integration under D206, its auth audit, atomic history and measured gates. -->

Merged `origin/tls-session` in `1694e11f`, preserving #158 final Close 4404, #151 session bounds and every production auth path/test. Bootstrap follow-up `0e6899c5` removes its production-only Cookie field-count guard; the shared strict parser now serves every reader. Its real-passkey/SQLite/socket regression fails before (0/1, 1.07 s) and passes after (1/0, 0.70 s), accepting either field order and denying duplicates/malformed/non-text fields. Review tests `59c72a49` replayed as `abb80a05` verify split ceremony reuse and refusal without consuming signed proof.

Validation: **608 Rust tests passed**, 0 failed, 64 ignored; auth **110 unit + 1 integration** passed; expanded native/proxy TLS **2 passed in 2.38 s** (registration/joined/split session all 200). Tracer check and **142 src tests**, protocol compiler and **36 tests / 34,462 assertions**, production build/transfer pass. Deferred Brotli **44,733 / 45,056 B**. Auth B1/S1/S2/N1 checklist completed; Origin, cookie flags, unlock/revocation, admission and ingress policy retained. Workspace lockfile regeneration is byte-identical; package/version/source sets unchanged.

Static x86_64: exact `04cdc52a` **19,992,512 B** → **19,991,488 B** (**−1,024 B**), no PT_INTERP. The known **16,404,816 B** limit remains unchanged; the size row stops before aarch64.

Local CPUWeight=10000 parser probes, infraternal-dev / 8 CPUs, 3 × 200,000 requests × 50 sessions: production `opt=s` median **287.49 → 313.39 ns/request**, **+1.295 µs/50 requests**; `opt=3` **110.27 → 219.53 ns/request**, **+5.463 µs/50**. Retained **0 B/session × 200 = 0 B**. `opt=s` load **22.76/18.03/17.24 → 24.41/18.72/17.49**. Parser averages, not end-to-end percentiles.

The initial tracer timing failure passed its scoped rerun. One unchanged Mesh snapshot socket-close failure passed two isolated runs and the complete gate retry: **10,000 nodes / 30,000 grants**, **88 pages**, **64,612 B** maximum frame, shared socket Pong. No failure waived or timeout changed.

`scripts/verify fast` summary, verbatim (exit 1 solely for known size):

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

Every commit pushed to `tls-session-prod`; no deployment. Full evidence and final head: [#149](https://git.kayg.org/kayg/infraternal/issues/149). Raw logs remain under `$HOME/.cache/codex-scratch/tls-session-prod/`; temporary build targets/checkouts are removed at completion.
