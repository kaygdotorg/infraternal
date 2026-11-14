# R4b extension manifest

Research-only overlay on R4 kit source `4f84c800570b`. It adds a wireguard-go Linux reference at upstream commit `b3bc704ef0ee21a36298601a9e1e5ff90377ac52` and uses wireguard-tools commit `a998407747005ea7e4e0258d96f105c97241e1d3` only to seed kernel peer tables. The peer-scale matrix keeps one traffic peer active while it measures 1, 100, and 1,000 configured peers per endpoint. For every engine and GotaTun source, it records idle RSS after the common quiet interval and loaded RSS while the same one-flow TCP and latency probes run. The per-process RSS sample is recorded by `proc-mem`; kernel peer memory remains a separately labeled slab or meminfo delta, not process RSS. Tailscale remains at the two-node testcontrol fixture's one peer; synthesizing a 1,000-node control map is outside this fixture.

At each peer count, the idle sample waits for the same 15-second quiet interval
before recording process memory with `proc-mem`; the loaded sample is
collected one second into the active five-second TCP measurement. RSS is read
from `/proc/<pid>/status` `VmRSS`, and PSS from `/proc/<pid>/smaps_rollup`
`Pss`. The same selected process-tree method applies to every userspace engine.
Raw status and `smaps_rollup` files remain beside each memory JSON. The scenario
table reports idle and loaded PSS MiB and bytes per peer beside VmRSS; kernel
rows have no userspace PSS value.

The source-aware matrix runs plain kernel WireGuard and wireguard-go alongside
the shipped GotaTun source and the J88i fairness, J316, J225+J316, and J324
candidates in five counterbalanced windows per scenario. J88i fairness is
`33ca6fe616587db506b16612f2a4b5bbd54997f3`. J316's checksum fix is pushed at
`f3197d046f385d38c39210dec651e0ba8e096b12`. The listed J316 `b678934` and
J225 stack `21a8a15` are pre-fix historical sources; the old stack is not a
current measurement candidate. Wait for J225's rebase and 1-flow smoke
handoff before measuring a combined row. It retains the D348 placement audit,
common probes and MTU, failed calibration evidence, owner-directed row label,
idle and loaded per-peer memory evidence, and one scenario table plus JSON with
raw logs. Candidate binaries use the same matrix CLI and controls, with their
full source SHA recorded in JSON and tables.

`R4B_REFERENCE_MANIFEST.txt` records the wireguard-go and `wg` binary hashes and ELF details. The perf VM contains the referenced Nix loader; `ldd` resolved both binaries there before the sweep.

All performance commands still run through `perf-run --root`; every case keeps the R4 before/after machine-diff cleanup check. No product code is changed.

Each pinned hold captures `perf.slice`'s exact `DropInPaths`, `AllowedCPUs`
value, runtime drop-in bytes, owner, group, mode, and mtime before changing
placement. The runner applies the D348 layout for the hold, restores those
runtime files byte-for-byte, reloads systemd, and checks the saved paths,
bytes, metadata, and `AllowedCPUs` in-scope. Its transient `perf-run` scope
remains inside `perf.slice`, so the parent cgroup mask can stay widened until
that scope exits. The second locked `perf-run` checks the original cgroup masks
after scope exit and rechecks the exact files and property; other slices still
fail closed if they already have drop-ins.

`R4B_EXTENSION.sha256` covers the source kit files present in this tree.
`build-kit` generates the packed kit's `MANIFEST` after it assembles binaries and
scripts; that manifest records checksums for the exact archive contents.
