# J1226 adoption check (#260): dev against the seeded-foldhash head, cross-VM, 2026-11-25

Rows I = infraternal static x86_64 musl of origin/dev `082f9d84b`; H = the same plus the J1226 head
(`8ef188c3a`: GotaTun fork `a0be34f8` and the seeded slot hash in the mesh packet filter). Same kit as J1204
(`../../kit-macro`), one hold `m1`, order I.1 H.1 H.2 I.2 (A/A pairs inside the hold), cubic, 1 and 8 flows,
both directions, 60 s windows, perf VMs calternal-perf-01 (A) and infraternal-perf-01 (B), lock held, private
netns with the guard. CPU is whole-machine busy time of A and B together. Raw: `windows-m1.csv`, `rows-m1.csv`.
The first hold, below, is `m1`; the reverse-order hold `m2` was run later by J1252 (second section).

| cell | holds | Gbit/s I | Gbit/s H | Δ Gbit/s | CPU s/Gbit I | CPU s/Gbit H | Δ CPU/Gbit | A/A gap Gbit/s | A/A gap CPU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| forward cubic1 | 1 | 3.081 | 3.085 | +0.1% | 1.246 | 1.211 | -2.8% | 0.4% | 0.5% |
| forward cubic8 | 1 | 3.145 | 3.149 | +0.1% | 1.261 | 1.239 | -1.8% | 0.5% | 0.6% |
| reverse cubic1 | 1 | 3.233 | 3.285 | +1.6% | 1.078 | 1.038 | -3.7% | 1.4% | 1.7% |
| reverse cubic8 | 1 | 3.226 | 3.272 | +1.4% | 1.062 | 1.008 | -5.1% | 0.6% | 9.7% |

Read (hold m1 alone): CPU per Gbit is lower in every cell (-1.8% to -5.1%), beyond the A/A gap except reverse 8 flows
(gap 9.7% on CPU); Gbit/s is unchanged forward and +1.4..1.6% reverse. J1204's two holds on the same patch
gave -1.6/-2.8% forward, -1.5/-0.2% reverse.

## Hold m2, reverse order (J1252, 2026-11-26)

Same kit, order H.1 I.1 I.2 H.2, 05:25-05:57Z, 16 windows, all exit 0, guard counters 0 packets on
both VMs. Rows I = `ad9764ae3` (`698623bf3^1`, dev just before the J1226 merge); H = `698623bf3`
(that merge), so I and H differ by J1226 only. Hold m1 used an older base (`082f9d84b`), so compare
I with H inside a hold, not rows across holds. Static x86_64 musl, sha256 (first 16 hex digits):
`infraternal` I `88f0dec9a721181d`, H `ef83d5f23d838d8a`. Kit changes against `../../kit-macro`: paths
renamed, the lock script raises its marker only once the locks are held, binaries are staged inside
the job's own hold, and a failed lock wait no longer tears down the network namespace. Raw:
`windows-m2.csv`, `rows-m2.csv`; the hold directories and the kit as run are attached to #260.

| cell | holds | Gbit/s I | Gbit/s H | Δ Gbit/s | CPU s/Gbit I | CPU s/Gbit H | Δ CPU/Gbit | A/A gap Gbit/s | A/A gap CPU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| forward cubic1 | 1 | 3.075 | 3.085 | +0.3% | 1.226 | 1.209 | -1.4% | 0.7% | 0.7% |
| forward cubic8 | 1 | 3.140 | 3.155 | +0.5% | 1.249 | 1.232 | -1.4% | 0.4% | 0.7% |
| reverse cubic1 | 1 | 3.277 | 3.302 | +0.7% | 1.068 | 1.053 | -1.5% | 1.0% | 2.5% |
| reverse cubic8 | 1 | 3.252 | 3.320 | +2.1% | 1.025 | 1.001 | -2.3% | 1.0% | 3.6% |

## Combined verdict (m1 + m2)

`macro_pairs.py` over both CSVs: median of the per-hold deltas, largest A/A gap of either hold.

| cell | holds | Gbit/s I | Gbit/s H | Δ Gbit/s | CPU s/Gbit I | CPU s/Gbit H | Δ CPU/Gbit | A/A gap Gbit/s | A/A gap CPU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| forward cubic1 | 2 | 3.078 | 3.085 | +0.2% | 1.236 | 1.210 | -2.1% | 0.7% | 0.7% |
| forward cubic8 | 2 | 3.143 | 3.152 | +0.3% | 1.255 | 1.235 | -1.6% | 0.5% | 0.7% |
| reverse cubic1 | 2 | 3.255 | 3.293 | +1.2% | 1.073 | 1.045 | -2.6% | 1.4% | 2.5% |
| reverse cubic8 | 2 | 3.239 | 3.296 | +1.8% | 1.043 | 1.005 | -3.7% | 1.0% | 9.7% |

- **Forward, 1 and 8 flows: confirmed.** CPU per Gbit -2.1% and -1.6%, beyond the 0.7% gap; in both
  holds both H rows are below both I rows. Throughput unchanged.
- **Reverse, 1 flow: lower, small.** -3.7% (m1) and -1.5% (m2). In m1 both H rows are below both I
  rows; in m2 the rows overlap and the delta is inside that hold's 2.5% gap.
- **Reverse, 8 flows: same sign, size not established.** m2 narrows the A/A gap from 9.7% to 3.6%,
  but its delta (-2.3%) is still inside it. m1's -5.1% leans on one high baseline row (I.2, 1.113
  s/Gbit); against I.1 alone it is -0.3%. Do not quote -3.7% for this cell; two holds do not
  separate it from noise.
- **Throughput:** no cell is lower with H. Reverse is +0.7..+2.1% per hold, the same sign in both,
  and about the size of the A/A gaps.

The adoption stands: no regression in any cell, and a CPU gain of about 1.5-2% that is clear in the
forward direction.
