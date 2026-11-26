# What ran

- Source base: origin/dev de6f9dce6 (GotaTun pin e87fef91) + `../harness/hub-bench.patch`. Hub test binary built on
  infraternal-dev-01-compute01 with `CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=1 cargo test --release
  -p infraternal-plugin-mesh --lib --features agent,test-support,cutoff-measure --no-run` (release optimisations; the
  debug info only adds symbols), run on the perf VM through the nix glibc loader (`ld-linux-x86-64.so.2 --library-path`).
- peersim: `../harness/peersim`, `cargo build --release`, boringtun 0.6.
- Files on infraternal-perf-01 (sha256, after the last update before the r2/r3/aqmoff/single/known holds):

```
a7bb2e904896727a7ae6a981fe74c67e075f53a04c12d36112a59c99fbba61fa  bin/hubtest
c7d251a1625225f67e22bef99d77663ae192a5b8c935d23e13d6f1bf10e2296d  bin/peersim
39af66f7d87488f9b400d33368ee59f65ccbc90af164e55b7a5b04d36d49f3ba  all.sh
5b232746d5860ba18be15d820a5760fd855f11a688d53a5303903ca04c30d15d  run.py
6.12.113+deb13-amd64
6
```

- r1-spread was run with an earlier `run.py` (rate points max and 400 Mbit/s only, one idle window per state, simulator
  silent during idle windows) and an earlier peersim (1 s retry); its idle rows after connect are not used. The hub binary
  `hubtest` and the cold-storm / apply / memory / throughput rows are comparable with r2 and r3.
- Holds (each one `perf-run --root`): r1 spread (17:24 UTC), aqmoff spread N=1000,4096 (`--hub-env GOTATUN_AQM=off --ks 100`),
  r2 spread (19:42 UTC), r3 spread, then single and known N=1000,4096 (21:00 UTC, `all.sh r1 single|known 1000 4096`).

# Raw receipts moved out of the repository (J1244)

The repository artifact size gate (`scripts/verify.d/evidence-size.py`) forbids `.log` files and any file over
200,000 bytes. These 55 files were removed from the tree in the commit that adds this section. They are packed in one
archive, attached to #260:

- Archive: `many-peer-hub-2026-11-25-raw-receipts.tar.gz` (49,506 bytes), 55 entries
- sha256: `b8f32e8cf72430defa75b54ee5fdffd0f0ad72e1f85b61f094aef2d1fe2e9514`
- Link: https://git.kayg.org/attachments/fd8a3316-721a-484a-9e2e-5911d27a138e (comment on #260)
- Listing: `tar -tzf many-peer-hub-2026-11-25-raw-receipts.tar.gz`; extract with `tar -xzf` into an empty directory.

Paths inside the archive are relative to this directory (`research/many-peer-hub/2026-11-25/`):

- 54 `.log` files: `raw/out-aqmoff-spread/` (6), `raw/out-r1-known/` (6), `raw/out-r1-single/` (6),
  `raw/out-r1-spread/` (12), `raw/out-r2-spread/` (12), `raw/out-r3-spread/` (12). These are the `run-*.log`,
  `stages-*.log` and `hub-stderr-*.log` files of each hold.
- `results.csv` (218,345 bytes, over the 200,000-byte limit): the combined table of all holds. `summary.md` cites it.

Files that stay in the repository: every `pivot-*.md`, `summary.md`, `MANIFEST.md`, the `profile/` text, the `.jsonl`
and per-hold `.csv` receipts, the `nft-*.txt` rulesets and the `raw/pr/` snapshots. `summary.md` still cites
`results.csv`; that file is in the archive only.
