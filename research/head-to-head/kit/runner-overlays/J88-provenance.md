# J88 measurement provenance

- Fork: `kaygdotorg/gotatun`, branch `j88-linux-offloads`, head `8c17cb1abe9b4cd8b7661dcce7d62d6d47552e38`.
- Source base: GotaTun v0.10.2, `1d46b779f5e0743f30a13cc2c325b8114b901fb9`.
- Upstream starting points, retained for later tracking: UDP GSO PR #170 head `2c4f97e9598a8f5fb64ab7c2e7083ac3ebfa20e4`; TUN TSO PR #10 head `bfd9f0d2f87d2716270c674d91321a241b61f534`.
- License checked: MPL-2.0 in LICENSE, Cargo metadata and crate SPDX; `flake.nix` still says BSD-3-Clause and needs reconciliation before distribution.
- Patched GotaTun binary: SHA-256 `ffc73a610f1be5625cd22ddfec9b2f0955f49bc61c42bb5ad64cb893b7d3be9a`, built on compute01 and linked to glibc 2.44 for perf VM compatibility.
- R4b GotaTun v0.10.2 baseline binary: SHA-256 `72ac6cdc09f2691d3225a732ce7ee7ca40ff37d79edd3a5d6f9ddbfb57490128`.
- wireguard-go reference binary: SHA-256 `26f64ade377d0336ad1b50839c26992976422dac99c11b72f40763ebe469d952`.
- Infraternal kernel-WireGuard harness binary: SHA-256 `b2cec7a205c522dff4f0f68c07bb2e1da93a9f81f234111ef29420bb2a5d4ed1`.
- Base harness overlay SHA-256: `e916d99a217dfb148bb86c557545ab5043bf8c98289efc1c257f829449819cdc`.
- Reordering environment forwarding overlay SHA-256: `b3390c2ba17397da44de1d60860bf24b9ad2643306f68e7edac44efda9b599ce`.
- Base overlay adds before/after aliases for unchanged kernel WireGuard and wireguard-go controls, GotaTun before/after plus mixed endpoints, and variant-aware reporting. The second overlay passes `H2H_REORDER_CHECK` through the perf-run wrapper. The existing independent 2% per-direction loss profile remains enabled; GotaTun variants also ran 198 ms RTT with 25% correlated packet reordering.
- First sweep results: `/home/claude/j20/r4b/h2h-kit/results/20261102T062117Z`; all cases exit 0 and have empty diffs except mixed peers, whose sole diff is a rotating `/root/.cache/nix/sentry/*.run` entry. That first run also did not propagate the reorder flag.
- Corrected GotaTun sweep results: `/home/claude/j20/r4b/h2h-kit/results/20261102T064841Z`; before, after and mixed cases exit 0, have empty diffs and no `.failed` measurements. Use these GotaTun rows for the final table and reorder results.
- Initial sweep controls: kernel WireGuard and wireguard-go before/after aliases use byte-identical binaries; only GotaTun changed.
- Build checks on compute01: `cargo fmt --all -- --check`; `git diff --check`; GotaTun library suite `86/86` passed with `tun,socket,ring`; release CLI built.
