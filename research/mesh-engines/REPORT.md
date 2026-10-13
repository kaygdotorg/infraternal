<!-- Role: Research comparison of userspace WireGuard engines and Linux kernel control clients for grill #79. SPDX-License-Identifier: AGPL-3.0-only -->

# WireGuard engine measurements for the mesh

> Historical raw receipts were removed under D262. Fresh output belongs under `$HOME/.cache/codex-
> scratch/mesh-engines/evidence/`; selected results should be attached to #81 with the `issue-
> attach` helper.

- **Issue:** #81
- **Measured:** 2026-10-07 on `infraternal-dev`
**Decision boundary:** Decisions 163–167 leave the engine choice to the owner. This report measures and recommends candidates; it makes no product choice and changes no product code.

## Findings for the grill

| Question | Measured result | Recommendation to carry forward |
| --- | --- | --- |
| Userspace engine | Four maintained, general-purpose engines were measured on Linux. Rust candidates reached 514–989 Mbit/s at four streams; the Go candidate reached 1,541 Mbit/s. All are well below the kernel reference. Rust candidates add about 18.8–20.7 KB per peer; Go adds about 37.6 KB per peer at 1,000 peers. | No candidate currently clears the full macOS + Windows + old-Linux, AGPL-compatible, one-Rust-binary constraint. GotaTun's audited Rust protocol core is the closest fit for an adapter follow-up, subject to replacing its WTFPL TUN crate and resolving Windows driver distribution. NepTUN is the fastest Rust result, but its current source still omits specified data-packet padding and its CLI has no Windows TUN path. The owner should decide whether to grill a split protocol-engine/TUN-adapter design. |
| Linux kernel control | `nl-wireguard` and a small typed client both applied 1,000 peers correctly in 62–66 ms. The typed client updated one peer in 10 μs. `nlink` 0.29.0 failed a one-message 1,000-peer apply with `EINVAL`. | Prefer the typed client using `netlink-bindings` plus `netlink-socket2`, with 400-peer request chunks, if a small owned client is acceptable. `nl-wireguard` is the less custom alternative and passed all checks. Do not use `nlink` for a 1,000-peer full-set path until it chunks requests. |
| Linux kernel vs userspace | Kernel WireGuard reached 2,280 / 2,658 Mbit/s at one / four streams. The fastest Rust userspace result, NepTUN, reached 956 / 989 Mbit/s; Go reached 1,345 / 1,541 Mbit/s. | Keep kernel WireGuard as the Linux path when present. Userspace remains a portability fallback for systems without the module; these samples do not support using userspace on Linux for speed. |

The Windows TUN path is a material open constraint. Wintun source is GPL-2.0-only and its prebuilt DLL has a separate custom license. Those terms are outside the repository's stated allowlist (MIT, Apache-2.0, BSD, ISC, MPL-2.0, and GPL-3.0-compatible licenses). The Go and GotaTun integrations can call Wintun, but their wrapper crates do not change the underlying DLL/driver terms. See [Wintun source project](https://github.com/WireGuard/wintun/blob/master/wintun.proj) and [prebuilt binary license](https://github.com/WireGuard/wintun/blob/master/prebuilt-binaries-license.txt).

## 1. Userspace engine candidates

The measured set is limited to maintained, general-purpose WireGuard implementations with a Linux CLI or device API that can be exercised through a system TUN. The platform TUN descriptions below come from project source and documentation; no macOS or Windows host was available for a native test.

| Engine | Source tested / release state | License | Audit and public security state | macOS and Windows TUN | Embedding in the Rust daemon |
| --- | --- | --- | --- | --- | --- |
| BoringTun | Source `6dcc889a95ad82400932f785d874421d70308195` (2026-06-15); crate/changelog 0.7.1 (2026-05-01). The GitHub release page's latest CLI tag is older, v0.5.2. | BSD-3-Clause, compatible. | No independent audit or published GitHub advisory found. Open #494 reports missing 16-byte data padding, exposing exact inner lengths; open #495 reports a 0.7.1 one-way-deaf regression. These are reports, not independently confirmed findings. | CLI has a native macOS `utun` path. The Windows library target contains protocol code but no TUN adapter; the product would need a Windows packet adapter. | Rust crate/API, no separate language runtime. Straightforward protocol embedding; a Windows TUN adapter and device lifecycle still need integration. The upstream CLI is Linux/macOS only. [Repo](https://github.com/cloudflare/boringtun), [changelog](https://github.com/cloudflare/boringtun/blob/master/CHANGELOG.md), [releases](https://github.com/cloudflare/boringtun/releases), [security page](https://github.com/cloudflare/boringtun/security), [#494](https://github.com/cloudflare/boringtun/issues/494), [#495](https://github.com/cloudflare/boringtun/issues/495). |
| GotaTun | Source `777bf03a71210ff5ba442aa5deaa7496877e4e58` (2026-10-06); latest release 0.9.2 (2026-08-31). | MPL-2.0, compatible. | Assured audited the core implementation in 2026-01/02; its published summary lists 2 low findings, 9 notes, 1 good finding, and no major vulnerabilities. The audit excluded the CLI, external dependencies, and DAITA. It noted key-memory protection and dependency concerns. No published GitHub advisory found. | The CLI's `tun` crate supports macOS `utun` and Windows through `wintun-bindings`/`wintun.dll`. The `tun` crate 0.8.6 declares WTFPL, so that CLI dependency is outside the allowlist. GotaTun core can be built without the optional TUN feature, but requires another adapter. | Rust crate/API, no extra runtime. Best documented Rust library path in this set, but the audit did not cover its CLI or dependencies. Replacing the current TUN adapter is required before using the CLI path. [Repo](https://github.com/mullvad/gotatun), [releases](https://github.com/mullvad/gotatun/releases), [audit summary](https://github.com/mullvad/gotatun/blob/main/audits/2026-02-17-Assured.md), [security page](https://github.com/mullvad/gotatun/security), [`tun` 0.8.6 manifest](https://docs.rs/crate/tun/0.8.6/source/Cargo.toml.orig). |
| NepTUN | Source `ce185155e1639403cc40e01260d0830065a49555` (2026-10-06); latest GitHub release v1.0.8 (2025-07-21). The checked-out tag and CLI crate use different version schemes (`v3.0.6` tag; CLI crate 0.6.0). | BSD-3-Clause, compatible. | No independent audit or published GitHub advisory found. Open issue #13 concerns macOS `CLOCK_MONOTONIC` jumps. Current source retains the data-padding TODO, so the traffic-analysis concern in BoringTun #494 also applies by source inspection. | Linux/macOS CLI with native `utun`; Windows library target is protocol-only and leaves the device adapter to the integrator. | Native Rust library, no extra runtime. The protocol API is embeddable; production Windows packet I/O and device lifecycle are not supplied. [Repo](https://github.com/NordSecurity/NepTUN), [releases](https://github.com/NordSecurity/NepTUN), [#13](https://github.com/NordSecurity/NepTUN/issues/13), [padding TODO in current source](https://github.com/NordSecurity/NepTUN/blob/main/neptun/src/noise/session.rs), [BoringTun #494](https://github.com/cloudflare/boringtun/issues/494). |
| wireguard-go | Source `2631ce99a06f27120d581611cf125d68bc6aa565` (2026-10-06); no numbered GitHub releases. | MIT, compatible. | No published GitHub advisory found; no `SECURITY.md` or independent audit located in the checked-out source. | Native macOS `utun`; Windows uses Wintun through a Go binding that loads `wintun.dll` at runtime. The binding is MIT; the separately distributed DLL/driver license is not on the allowlist. | Go package can be wrapped through cgo and linked as a C archive, but the Go runtime is included. This is the only measured route that adds a second language runtime to the Rust process. It requires `CGO_ENABLED=1` and a target C toolchain for each cross-compiled platform. [Repo](https://github.com/WireGuard/wireguard-go), [Windows TUN source](https://github.com/WireGuard/wireguard-go/blob/master/tun/tun_windows.go), [Windows entry point](https://github.com/WireGuard/wireguard-go/blob/master/main_windows.go), [security page](https://github.com/WireGuard/wireguard-go/security). |

### Screened projects not included in the data-plane comparison

These projects appeared in the source sweep but did not meet the measurement boundary above. They are recorded to make the scope explicit; they do not have comparable `iperf3` results in this report.

| Project | Screen result |
| --- | --- |
| `tailscale/wireguard-go` | The reachable `main` branch was at `469159ecf7d108dc1d44f8789dedbb463b7bd3a6`, dated 2023-07-04, so the standalone fork was treated as stale rather than a maintained candidate. It reports no published advisory. [Source](https://github.com/tailscale/wireguard-go/security). |
| `urnetwork/userwireguard` | Active Go fork (source commit `d80fc01268a09cd8570e2d98568512777b6b1165`, 2026-10-06), MPL-2.0. Its only TUN implementation is an integrated userspace network path using `github.com/urnetwork/connect`, rather than a documented host `utun`/Wintun adapter. That API and packet path are not comparable to the tested system-TUN engines. [Repo](https://github.com/urnetwork/userwireguard). |
| `galang-rs/wireguard` | Go, MIT; source commit `5e0a2d05e3a37b51aac27ce29e794ed39ffa194e` (2026-04-05). It describes a custom userspace TUN and does not document a macOS `utun` or Windows Wintun adapter; no numbered release or independent audit was found. [Repo](https://github.com/galang-rs/wireguard). |
| `rustguard` | Rust source commit `385fe44de74517f1525e58c9c4dc10022a9231af` (2026-01-25); no numbered release. Its README says the license is still to be determined while the workspace manifest says MIT OR Apache-2.0; the documented fast-path is Linux-specific and no macOS/Windows support matrix is provided. [Repo](https://github.com/rich7420/rustguard). |
| Official `WireGuard/wireguard-rs` | Its mirrored README describes Linux operation, says not to use it in place of the kernel module there, and marks Windows as coming soon. It therefore does not satisfy the macOS + Windows target in this job. [Repo](https://github.com/WireGuard/wireguard-rs). |
| `DefGuard/wireguard-rs` | A management wrapper, not an independent protocol engine: its userspace path invokes BoringTun, while Windows support requires the WireGuard-NT DLL. No separate engine dataplane was measured. [Repo](https://github.com/DefGuard/wireguard-rs), [userspace backend source](https://github.com/DefGuard/wireguard-rs/blob/main/src/wgapi_userspace.rs). |

### Data-plane results

Median (minimum–maximum) across five independent samples. Throughput is Mbit/s. Added latency is the per-sample tunnel p50/p99 minus direct p50/p99, then summarized over the five samples. CPU is engine CPU-seconds per Gbit of received payload for both local endpoints.

| Engine | 1 stream | 4 streams | CPU/Gbit, 1 / 4 streams | Direct ping p50 / p99 ms | Tunnel ping p50 / p99 ms | Added ping p50 / p99 ms | RSS growth per peer at 100 / 1,000 peers |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux kernel | 2,280.24 (2,138.29–2,482.25) | 2,657.79 (2,371.21–2,829.71) | 2.442 (1.701–3.085) / 1.709 (1.546–2.853) | 0.035 (0.033–0.035) / 0.060 (0.051–0.110) | 0.154 (0.147–0.168) / 0.316 (0.264–4.120) | 0.121 (0.112–0.133) / 0.244 (0.204–4.069) | Not isolatable |
| BoringTun | 594.86 (533.02–624.65) | 586.40 (429.44–686.23) | 1.543 (1.474–1.607) / 1.954 (1.758–2.225) | 0.032 (0.031–0.035) / 0.058 (0.055–0.075) | 0.147 (0.143–0.159) / 0.544 (0.204–4.180) | 0.115 (0.112–0.127) / 0.486 (0.136–4.105) | 19,743 (19,743–19,784) / 18,760 (18,760–20,345) B |
| GotaTun | 598.48 (533.68–705.33) | 514.29 (504.18–573.63) | 1.895 (1.807–1.915) / 2.338 (2.231–2.410) | 0.035 (0.035–0.039) / 0.055 (0.050–0.095) | 0.216 (0.214–0.224) / 0.418 (0.297–4.210) | 0.181 (0.177–0.187) / 0.353 (0.238–4.155) | 20,398 (19,988–21,053) / 20,017 (19,960–20,181) B |
| NepTUN | 955.56 (817.20–1,146.39) | 988.90 (662.95–1,311.31) | 2.063 (1.952–2.285) / 2.368 (2.247–2.589) | 0.037 (0.035–0.038) / 0.056 (0.050–0.065) | 0.272 (0.263–0.291) / 4.210 (2.790–4.310) | 0.236 (0.226–0.256) / 4.154 (2.729–4.245) | 21,012 (20,931–21,463) / 20,652 (20,648–20,701) B |
| wireguard-go | 1,344.98 (1,033.06–1,762.46) | 1,541.02 (1,294.91–1,702.79) | 0.784 (0.774–0.987) / 0.884 (0.820–0.974) | 0.035 (0.034–0.037) / 0.078 (0.048–0.089) | 0.293 (0.264–0.307) / 0.629 (0.452–2.150) | 0.259 (0.227–0.270) / 0.540 (0.394–2.102) | 48,742 (40,387–53,166) / 37,614 (35,287–39,285) B |

The per-peer number is `(engine RSS with N peers − engine RSS at zero peers) / N`; it includes allocator and runtime effects. At 1,000 peers this corresponds to about 18.8 MB, 20.0 MB, 20.7 MB, and 37.6 MB of incremental resident memory per engine process for BoringTun, GotaTun, NepTUN, and Go respectively, plus each process's fixed RSS. Decisions 163–167 do not give a numeric expected node count, so the raw 100- and 1,000-peer points are reported rather than inventing a deployment scale.

Kernel WireGuard peer allocations are kernel-owned and not represented by the userspace process RSS. The harness sampled the enclosing cgroup's `memory.current`, but those values were noisy and sometimes fell after peer configuration, so the kernel per-peer memory result is deliberately `Not isolatable` rather than inferred from unrelated cgroup changes.

The p99 values are scheduler-sensitive here: several 100-ping samples include millisecond outliers under shared load. Do not rank engines by these p99 medians. The `ping` window is 100 packets at 10 ms; p50 and p99 use the 50th and 99th sorted samples.

### Release executable sizes

Bytes for the Linux x86_64 release artifacts used here. Rust command-line builds are upstream release-profile executables before and after `strip --strip-unneeded`; the Go executable is a stripped static build. These are complete CLI size proxies, not measured incremental size in the product binary.

| Artifact | Release bytes | Stripped bytes | Build note |
| --- | ---: | ---: | --- |
| BoringTun CLI | 1,599,168 | 1,306,712 | Rust release profile |
| GotaTun CLI | 2,723,040 | 2,261,256 | Rust release profile; includes the CLI TUN feature |
| NepTUN CLI | 1,818,752 | 1,483,408 | Rust release profile |
| wireguard-go | 3,313,824 | 3,312,248 | `CGO_ENABLED=0`, `-trimpath`, `-ldflags '-s -w'`; static Go runtime |

The Go c-archive measurement links a Rust host that creates and closes a real TUN device inside a rootless user/network namespace. Across two builds from the same source revision, the archive was 4,331,184 B and the stripped Rust host was 3,870,512 B, against a 332,688 B empty Rust host: **+3,537,824 B**. The two raw samples are in [go-embedding.csv](results/go-embedding.csv); the build is reproducible with [measure-go-embedding.sh](scripts/measure-go-embedding.sh). This is an exact Linux host delta for the measured bridge, not a macOS or Windows cross-build result.

For context only, the stripped standalone control harness executables were 1,061,560 B (`nl-wireguard`), 459,896 B (typed minimal), and 1,589,752 B (`nlink`). They include benchmark code and are not incremental product-size deltas. Full measurements are in [artifact-sizes.csv](results/artifact-sizes.csv).

## 2. Linux kernel WireGuard control from Rust

Every successful client was checked against a real kernel WireGuard interface. The benchmark installed 1,000 peers with distinct public keys and one IPv4 allowed IP per peer, changed one peer's allowed IP while retaining all others, removed one peer, read back the listen port and peers, and read live handshake/traffic statistics after a real handshake and ping.

| Client | Apply 1,000 peers, μs | One-peer update with 1,000 present, μs | Remove one peer, μs | Correctness result | Standalone stripped harness | Direct dependencies and licenses |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| `nl-wireguard` 0.3.0 | 61,747 (49,922–69,963) | 60 (34–98) | 217 (153–236) | Peer count/keys, allowed IPs, listen port, removal, and live handshake stats verified. | 1,061,560 B | `nl-wireguard` MIT; direct dependencies: `base64`, `futures-channel`, `futures-util`, `genetlink`, `log`, `netlink-packet-core`, `netlink-packet-generic`, `netlink-packet-wireguard`, `netlink-proto`, `netlink-sys`, and Tokio; all direct licenses are MIT or MIT OR Apache-2.0. |
| Typed minimal client | 66,333 (48,386–70,374) | 10 (7–21) | 198 (146–543) | Same checks passed. Uses 400-peer chunks (three SET_DEVICE requests) and generated typed attribute encoding/decoding. | 459,896 B | `netlink-bindings` 0.3.5 and `netlink-socket2` 0.3.5, both MIT OR Apache-2.0; direct `libc` dependency is MIT OR Apache-2.0. |
| `nlink` 0.29.0 | Full 1,000-peer apply rejected in 2,535 (2,446–5,994) | 58 (43–78) | 5,651 (182–6,085) | Direct full-set apply returns `EINVAL` (`bytes leftover after parsing attributes`). Update/remove/readback pass after loading the baseline through the chunking `nl-wireguard` client. | 1,589,752 B | `nlink` MIT OR Apache-2.0; direct dependencies include `bitflags`, `bytes`, `libc`, `netlink-sys`, `nlink-macros`, `thiserror`, Tokio, `tokio-stream`, `tracing`, `winnow`, and `zerocopy`, all with compatible MIT/Apache/BSD terms. |

`nl-wireguard` loaded the `nlink` fallback baseline in 73,355 μs (56,068–85,562). The `nlink` failure is not a kernel capacity finding: its attempted single peer-list request exceeded the kernel parser's accepted payload, while the three-request typed client and `nl-wireguard` both applied the set. The five raw rows are in [nl-wireguard.csv](results/nl-wireguard.csv), [netlink-minimal.csv](results/netlink-minimal.csv), and [nlink.csv](results/nlink.csv).

The measured package roles and licenses are distinct:

| Package | Role in the client | License / disposition |
| --- | --- | --- |
| `nl-wireguard` | WireGuard Generic Netlink API with peer configuration and readback. | MIT; compatible. [Docs](https://docs.rs/nl-wireguard/0.3.0/nl_wireguard/). |
| `nlink` | Broad async Linux netlink API with a WireGuard module. | MIT OR Apache-2.0; compatible. It failed the full-set correctness test at 1,000 peers. [Docs](https://docs.rs/nlink/0.29.0/nlink/). |
| `netlink-bindings` + `netlink-socket2` | Generated typed WireGuard attributes plus a small synchronous socket client. | Both MIT OR Apache-2.0; compatible. [Bindings](https://docs.rs/netlink-bindings/0.3.5/netlink_bindings/), [socket](https://docs.rs/netlink-socket2/0.3.5/netlink_socket2/). |
| `netlink-packet-wireguard` | Typed packet encode/decode building block; does not own a complete socket/client loop. | MIT; compatible. [Docs](https://docs.rs/netlink-packet-wireguard/0.5.0/netlink_packet_wireguard/). |
| `wireguard-control` | Existing cross-platform control API, not selected for the measured Linux netlink candidates. | LGPL-2.1-or-later, outside the stated allowlist; excluded before benchmarking. [Crate](https://crates.io/crates/wireguard-control). |

### Linux control recommendation

The typed minimal client was fastest for a one-peer update and had the smallest standalone harness. It costs roughly 4.6 ms more than `nl-wireguard` to apply 1,000 peers in these samples, while its update path was 50 μs faster at the median. Both apply paths are comfortably below a tenth of a second on this host. If owning a small client is acceptable, the typed bindings plus socket crate and bounded chunks are the strongest measured option. If minimizing project-owned protocol code is more important, `nl-wireguard` passed the same full correctness checks with similar apply time. `nlink` needs a chunked apply path before it is considered for this workload.

## 3. Linux kernel vs best userspace reference

| Path | 1-stream throughput | 4-stream throughput | Added ping p50 / p99 | CPU seconds/Gbit, 1 / 4 streams | Per-peer process RSS growth at 1,000 peers |
| --- | ---: | ---: | ---: | ---: | ---: |
| Kernel WireGuard | 2,280 Mbit/s | 2,658 Mbit/s | 0.121 / 0.244 ms | 2.442 / 1.709* | Not isolatable |
| Best Rust userspace, NepTUN | 956 Mbit/s | 989 Mbit/s | 0.236 / 4.154 ms | 2.063 / 2.368 | 20,652 B |
| Best overall userspace, wireguard-go | 1,345 Mbit/s | 1,541 Mbit/s | 0.259 / 0.540 ms | 0.784 / 0.884 | 37,614 B |

*Kernel CPU time counts `wg-crypt` workers only; it excludes softirq and other network-stack CPU. Userspace CPU counts both engine processes' thread CPU. The CPU figures are therefore not apples-to-apples and should not be used as a kernel-vs-userspace ranking.

The kernel path delivered 2.4–2.7× the fastest Rust user's throughput, and 1.7–1.8× the Go result. Kernel p50 latency was near the best observed userspace p50; p99 is too noisy under this host's scheduler load to support a fine ranking. The process RSS measurements show the Rust processes growing by about 20–21 MB per 1,000 peers, versus about 37.6 MB for Go, before each process's fixed memory. This supports the Linux-kernel path in Decisions 163 and 167 where the module exists.

## Method and reproducibility

### Host and load

The test host was `infraternal-dev`, Debian 13 x86_64, Linux `6.12.111+deb13-amd64`, 8 vCPUs (Intel Core i9-9900K at 3.60 GHz), 32 GiB RAM. The five-run series shared this host with other jobs. Each sample was launched under `systemd-run --user --scope -p CPUWeight=10000`; the cgroup's `cpu.weight` read back as 10000. This is a scheduling weight, not an exclusive CPU reservation. The start load averages (1/5/15 minutes, median and min–max) were:

| Engine | 1 min | 5 min | 15 min |
| --- | ---: | ---: | ---: |
| Kernel | 34.80 (30.23–35.78) | 27.79 (26.41–28.60) | 20.61 (19.98–21.06) |
| BoringTun | 29.13 (28.62–29.60) | 23.62 (23.35–24.09) | 17.94 (17.70–18.21) |
| GotaTun | 31.12 (29.68–31.93) | 25.26 (24.60–25.75) | 18.89 (18.54–19.22) |
| NepTUN | 26.11 (24.70–27.09) | 24.99 (24.77–25.14) | 22.29 (22.27–22.33) |
| wireguard-go | 28.54 (26.75–29.49) | 25.70 (25.49–25.91) | 19.46 (19.34–19.71) |

The raw host checks are in [environment.txt](results/environment.txt). In a rootless `unshare -Urnm` namespace, `ip link add type wireguard` and `ip tuntap add dev meshprobe0 mode tun` both succeeded and were deleted afterward. The userspace engine samples themselves also created TUN interfaces in their isolated namespaces. `/dev/net/tun` was present.

### Data-plane harness

[`run-tunnel-sample.sh`](scripts/run-tunnel-sample.sh) creates a rootless network namespace and a second network namespace connected by veth. It runs direct ping, then a real WireGuard handshake and tunneled ping; `iperf3` sends for three seconds with `-P 1` and `-P 4`. [`repeat-tunnel-samples.sh`](scripts/repeat-tunnel-samples.sh) runs five fresh scopes per engine. Each sample records start/end load average, p50/p99, `iperf3` received bytes and throughput, CPU ticks, and RSS at zero, 100, and 1,000 synthetic peers.

User-space CPU is the sum of both engine processes and threads during the `iperf3` transfer. Kernel CPU is the sampled `wg-crypt-wgL`/`wg-crypt-wgR` worker CPU only; the kernel's other networking CPU is not attributed. Memory is one userspace daemon process; kernel cgroup measurements were discarded as not attributable. The 100- and 1,000-peer entries use distinct synthetic public keys and unique IPv4 /32 allowed IPs. No private keys are stored in files, argv, or logs.

The source sweep and measurements were captured on 2026-10-07. The host had `rustc 1.99.0 (b940084d7 2026-09-28)` and Go 1.27.1. Rust CLI artifacts used each upstream release profile and a separate target directory. The Go CLI used `CGO_ENABLED=0`, `-trimpath`, and `-ldflags '-s -w'`. The source table records the exact commits; these commands reconstruct the tested checkouts and release binaries (the separate scratch path keeps compiler outputs out of this worktree):

```sh
SCRATCH="$HOME/.cache/codex-scratch/mesh-engines"
mkdir -p "$SCRATCH/src" "$SCRATCH/bin"
git clone https://github.com/cloudflare/boringtun "$SCRATCH/src/boringtun"
git -C "$SCRATCH/src/boringtun" checkout --detach 6dcc889a95ad82400932f785d874421d70308195
git clone https://github.com/mullvad/gotatun "$SCRATCH/src/gotatun"
git -C "$SCRATCH/src/gotatun" checkout --detach 777bf03a71210ff5ba442aa5deaa7496877e4e58
git clone https://github.com/NordSecurity/NepTUN "$SCRATCH/src/neptun"
git -C "$SCRATCH/src/neptun" checkout --detach ce185155e1639403cc40e01260d0830065a49555
git clone https://github.com/WireGuard/wireguard-go "$SCRATCH/src/wireguard-go"
git -C "$SCRATCH/src/wireguard-go" checkout --detach 2631ce99a06f27120d581611cf125d68bc6aa565

(cd "$SCRATCH/src/boringtun" && CARGO_TARGET_DIR="$SCRATCH/target/boringtun" cargo build --release --locked -p boringtun-cli)
(cd "$SCRATCH/src/gotatun" && CARGO_TARGET_DIR="$SCRATCH/target/gotatun" cargo build --release --locked -p gotatun-cli)
(cd "$SCRATCH/src/neptun" && CARGO_TARGET_DIR="$SCRATCH/target/neptun" cargo build --release --locked -p neptun-cli)
(cd "$SCRATCH/src/wireguard-go" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$SCRATCH/bin/wireguard-go" .)
```

For the netlink control harness, run `cargo build --release --locked --manifest-path research/mesh-engines/netlink-bench/Cargo.toml`, then repeat with `--features nlink-bench`. The measured standalone size is after copying each release executable and applying `strip --strip-unneeded`; it is an executable-size proxy for the Rust CLI, not an incremental link delta in the daemon. `measure-go-embedding.sh` separately links the pinned Go engine as a C archive into a stripped Rust host and verifies that it creates a TUN device inside a rootless namespace.

Then set `WG_BIN`, `IPERF3_BIN`, and the candidate-specific `BORINGTUN_BIN`, `GOTATUN_BIN`, `NEPTUN_BIN`, or `WIREGUARD_GO_BIN` variable, and use:

```sh
research/mesh-engines/scripts/repeat-tunnel-samples.sh kernel > research/mesh-engines/results/kernel.csv
research/mesh-engines/scripts/repeat-tunnel-samples.sh boringtun > research/mesh-engines/results/boringtun.csv
research/mesh-engines/scripts/repeat-tunnel-samples.sh gotatun > research/mesh-engines/results/gotatun.csv
research/mesh-engines/scripts/repeat-tunnel-samples.sh neptun > research/mesh-engines/results/neptun.csv
research/mesh-engines/scripts/repeat-tunnel-samples.sh wireguard-go > research/mesh-engines/results/wireguard-go.csv
python3 research/mesh-engines/scripts/summarize.py > research/mesh-engines/results/summary.md
```

The runner performs each iteration in a fresh rootless namespace under its own CPU-weighted scope. Results can change with host load, kernel, compiler, crypto backend, and target. The command-line builds test protocol/device behavior, not a final product-integrated packet adapter.

### Control-plane harness

[`run-control-sample.sh`](scripts/run-control-sample.sh) creates a fresh pair of rootless namespaces and kernel WireGuard link for each sample. The `nl-wireguard`, typed-minimal, and `nlink` executables run the correctness sequence above; [`repeat-control-samples.sh`](scripts/repeat-control-samples.sh) repeats it five times. The Rust harness is in [`netlink-bench/`](netlink-bench/), with `Cargo.lock` recording resolved versions. `minimal.rs` uses `netlink-bindings` generated typed encoding/decoding and sends a maximum of 400 peers per request; it does not implement an unchecked raw-byte parser. Build with Rust 1.99.0 as shown above, then set `NETLINK_BENCH_BIN`, `NETLINK_MINIMAL_BENCH_BIN`, and `NETLINK_NLINK_BENCH_BIN` to the three release executable paths before running the repeat script.

### Raw result files

- [Engine data-plane samples](results/boringtun.csv), [GotaTun](results/gotatun.csv), [NepTUN](results/neptun.csv), [wireguard-go](results/wireguard-go.csv), and [kernel reference](results/kernel.csv).
- [Netlink samples](results/nl-wireguard.csv), [typed minimal](results/netlink-minimal.csv), and [nlink](results/nlink.csv).
- [Summary tables](results/summary.md), [candidate artifact sizes](results/artifact-sizes.csv), [Go embedding sizes](results/go-embedding.csv), and [host checks](results/environment.txt).

## Review checklist and limits

- [x] No product code changed; all output is under `research/mesh-engines/`.
- [x] Repeated five times per data-plane and control-plane candidate, with raw CSV rows retained.
- [x] Rootless kernel WireGuard, TUN creation, and the requested CPU-weight scope were verified on the host.
- [x] Correctness includes real peer readback, allowed IPs, listen port, removal, and live handshake/traffic stats.
- [x] Binary size is measured for release CLI artifacts; the Go host delta is measured separately with the engine path creating a TUN device.
- [x] Licenses, audits, public advisories, open findings, source revisions, and platform TUN constraints were reviewed and linked.
- [ ] Native macOS and Windows measurements remain outstanding; this host is Linux only.
- [ ] The process memory sample is one process on one Linux x86_64 host; it does not replace the project’s pinned multi-platform scale gate.
- [ ] `iperf3` tests one direction over a local veth pair, not a real WAN, relay, or India↔Germany path. Shared-host load makes p99 and CPU ranking noisy.
- [ ] No numeric expected mesh node count is present in Decisions 163–167; 100 and 1,000-peer RSS points are provided for later scaling.

No adoption decision is made here. The owner should decide the engine and TUN-driver license questions at grill #79 using these numbers and the remaining native platform/security work.
