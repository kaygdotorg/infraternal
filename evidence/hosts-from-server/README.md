<!-- Evidence index and measurement provenance for admitted host discovery, #194. -->
# Admitted host discovery evidence

The fixed comparison base is `efac27a598027a09abd008df952629a3cb549de5`, the initial
`origin/dev` base of this branch. Later movement of `origin/dev` is not the baseline.

Functional browser proof uses the production product canvas and binary mux test
fixture, fresh browser storage, an offline host admitted elsewhere, UUID shell
routing, reconnect without duplicate rows, and removal while the palette stays
open. `admitted-offline-host.png` is attached for owner/designer review. No new UI
surface or style was added and no visual-quality judgment is claimed.

The real-server measurement script is `scripts/hosts-from-server/measure.ts`.
It uses real PTYs, virtual passkey sign-in, public SQLite fixture admissions,
1,000 offline hosts, 12 fresh contexts per variant and fixed 300 ms RTT. Both
variants use the same prebuilt candidate server; the baseline frontend is built
from the fixed base. Browser instrumentation records the first glyph draw and
public action IDs, never terminal text, cookies or setup capabilities.
`sign-in.json` retains the samples. Its p99 field is the sample maximum with only
12 trials, not a statistically established tail percentile. Inventory precedes
that first draw in zero candidate trials. An eight-millisecond median difference
in the initial run is variation, not proof of zero latency cost; the ordering
check proves inventory requests are outside the initial terminal frame path.

All timings come from the named perf VM (4 vCPU, 7 GB), under
`flock -w 3600 /var/lock/perf-bench.lock`, held only for the measurement. Functional
build-host logs contain test-runner durations and are not performance evidence.

The static binary budget is independently red. The original fixed base produces
22,464,880 bytes on x86 against a frozen maximum of 16,404,816. The candidate
produces 22,512,464 bytes, an added 47,584 bytes. The gate and its budgets were not
changed. This branch cannot be reported as done while that gate is red.

The final native server used for the repeated measurement has SHA-256
`97e2413499a2cf574f68ac9c49d097f67ea8b5359460204eddbf5fd1aa75a6b4`
(source server changes through `940b2c4f`). The client readiness changes are
`171448cd`; `945ff59b` changes build-graph accounting only. The x86 baseline
artifact SHA-256 is `a43c7abb335a426c59798575337d9b2d84244c7bf8553f7440b14a340669ff1e`.

The TypeScript fast gate passes: 185 tracer tests, 36 protocol tests, critical
transfer 295,313 bytes gzip / 245,723 brotli, deferred transfer 50,985 bytes gzip /
45,056 brotli. The deferred brotli output is exactly its existing bound. The
failing-before graph test and the unchanged production budget output are retained.
