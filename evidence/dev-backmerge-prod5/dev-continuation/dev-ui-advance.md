<!-- Records the final D250 reconciliation of the owner's close-toast change and its functional evidence, #169. -->
# Later dev advance

Merge `2f94d955` joins `5b1e8b70` and owner commit `92e17ea7` (#196).
All eleven upstream files are retained verbatim, with no conflict or test
removal. Production add-host, Start fresh and ended-strip behavior remains
alongside the shared close toast and its first-use gate. D243/D244 checks and
native Rust sources are unchanged. Push only this branch; no deployment.

`ts-ui-advance.log` records four hint unit tests, 176 tracer tests and 36
protocol tests passing, with 34,462 protocol assertions and zero differential
divergences. Compiler, artifact checksums, production build and transfer
budgets pass: critical gzip 295,237/307,200 and Brotli 245,642/256,000 bytes;
deferred 49,794/51,200 and 43,966/45,056 bytes. The largest on-demand chunk is
15,852/20,480 gzip and 14,100/18,432 Brotli bytes.

`browser-ui-advance.log` records three unchanged functional toast cases
passing on unique port 4977 under an owned CPUWeight=10000 scope. The capture
at `captures/close-toast/reopen-desktop.png` uses the optimized browser build
and synthetic canvas fixtures. It is attached for independent visual review;
no author visual-quality verdict or physical-device proof is claimed.

The inherited forty add-host/Start fresh/ended-strip cases and full
`scripts/verify fast` are repeated on the final evidence head. Exact-head raw
output is quoted verbatim on #169. Earlier interrupted disk-full and dev-advance
transcripts remain explicitly non-final; no size or timeout exemption applies.
