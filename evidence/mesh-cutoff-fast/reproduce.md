<!-- Reproduce the D242 timing, parser and functional proofs without changing owner fixtures, #173. -->
# Reproduction

The baseline is original `5d098cb828190e48e25f7b3e9312c8212c02a63f` plus diagnostic-only scopes and the disposable public-state fixture (`baseline-diagnostics.patch`). The static-size comparison and auth reproduction use an entirely unmodified export of that revision. No baseline access encoding, application, persistence or retirement changes are made.

Build native release fixtures on infraternal-dev under an isolated `CARGO_TARGET_DIR` in `$HOME/.cache/codex-scratch/mesh-cutoff-fast/`. The coordinator requires the server `remote` feature and mesh `cutoff-measure`; the public-state fixture requires mesh `agent,server,cutoff-measure`. The recorded node build also enables `ee`, but the scenario explicitly initializes Allow then changes to Deny, so its edition default is unused. Release/dependency profiles stay unchanged. `bundle-native.py` changes only the private loader/search path and strips debug sections; it checks executable-segment SHA256 equality. Artifact metadata records both original and adapted hashes. The public-response compatibility repair did not change the measured node executable segments (`pre-removal-node-equivalence.json`). The final removal-plan artifact and its source-equivalence metadata are separately recorded.

Copy only the portable fixtures, their libraries and the existing proof scripts to `/root/infraternal-bench/mesh-cutoff-fast/` using `netbird ssh --no-browser root@10.69.69.208`. Every timing run uses:

```sh
cd /root/infraternal-bench/mesh-cutoff-fast
flock -w 3600 /var/lock/perf-bench.lock \
  systemd-run --user --scope -p CPUWeight=10000 \
  env INFRATERNAL_CUTOFF_MEASURE=1 unshare -Urn \
  python3 mesh-revocation-proof.py \
  --fixture ./removal-refusal-node --coordinator ./removal-refusal-coordinator \
  --stateful --extra-members 997 --rtt-ms 150 \
  --change DefaultTightening --budget-ms 200 --evidence ./sample
```

Add `--nf-tables` for the compatibility frontend. `campaign-batched.sh` records the baseline and first candidate; `campaign-removal.sh` records the final candidate. Each releases the lock between short batches of five independent disposable measurements. Each backend/variant has 31 samples. The first candidate remains recorded even though compatibility p99 misses the target. Nearest-rank p99 is the largest observed sample, not a precise estimate of a population percentile. The first per-sample queue attempt was stopped only while its own lock waiter was queued; samples 1–2 were retained and skipped by the resumed campaign.

Each sample has three configured real kernel nodes, 1,000 installed peer keys per node, two traffic receivers and three real coordinator workers on fixture channels. The remaining inventory entries are public-only keys. Fragmented changes exceeding the existing action budget and older nodes retain the original chunk path; the single-round-trip claim covers the measured uniform tightening. This is the archived round-4 workload; it does not measure 1,000 simultaneously connected control workers. After recording its final installation, the sender's filter is removed so it cannot hide receiver enforcement. Separate incoming/outgoing connection-state campaigns verify persistent sender enforcement. Timing includes all three installed-rule clocks, not only receivers. Successful durable application is mandatory before a fixture exposes its earlier installed-rule timestamp. Raw packet assertions refuse every packet sent after receiver installation, across IPv4/IPv6 TCP/UDP.

Early summaries counted receivers only; originals remain intact. `analyze.py` derives the stricter all-three-node cutoff and durable completion from recorded successful final-frame clocks, and preserves each original summary value. `analyze.py --check <sample>` rejects the original two-coordinate summary and accepts the corrected one. No clock is estimated. Stage logs distinguish compile, encode, acknowledgment, inventory, firewall, persistence and retirement; journal encoding/write diagnostics are separately available on the after build.

Functional packet/state/rollback/recovery and namespace-only tests run on infraternal-dev without collecting performance evidence. Parser fuzzing runs the existing exact `mesh_node_json` target on the locked VM with valid compact/probe and malformed seeds. Its ASan build disables release LTO only for the fuzz executable after the original LTO build failed to link coverage globals; shipping release profiles stay unchanged.

The fast gate uses the existing documented native qualification in `docs/verification/mesh-policy-verify/gates/gate-profile.toml`, `RUST_TEST_THREADS=1`, the private short test-state root and `TRACER_TEST_PORT=4493`. `gate-cargo` records that wrapper; it disables the compiler cache after an isolated namespace compiler attempt reported unreachable networking, without stopping or changing any shared cache process. `gate-python3` routes only the required RTT self-test to the locked VM; every other Python invocation is unchanged. Both static targets and all original budgets run. No gate failure is waived.

Extract `raw-samples.tar.gz` here before running `python3 analyze.py`. Original summaries and raw traces are preserved unchanged inside the archive.

`verification-logs.tar.gz` retains the exact build, gate, auth-repeat, failing and passing functional logs. Generated Python bytecode is excluded. The final head gate output is also quoted on #173.
