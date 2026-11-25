# J1226 adoption check (#260): dev against the seeded-foldhash head, cross-VM, 2026-11-25

Rows I = infraternal static x86_64 musl of origin/dev `082f9d84b`; H = the same plus the J1226 head
(`8ef188c3a`: GotaTun fork `a0be34f8` and the seeded slot hash in the mesh packet filter). Same kit as J1204
(`../../kit-macro`), one hold `m1`, order I.1 H.1 H.2 I.2 (A/A pairs inside the hold), cubic, 1 and 8 flows,
both directions, 60 s windows, perf VMs calternal-perf-01 (A) and infraternal-perf-01 (B), lock held, private
netns with the guard. CPU is whole-machine busy time of A and B together. Raw: `windows-m1.csv`, `rows-m1.csv`.
One hold only: a second hold (reverse order) did not get the perf VMs before the deadline.

| cell | holds | Gbit/s I | Gbit/s H | Δ Gbit/s | CPU s/Gbit I | CPU s/Gbit H | Δ CPU/Gbit | A/A gap Gbit/s | A/A gap CPU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| forward cubic1 | 1 | 3.081 | 3.085 | +0.1% | 1.246 | 1.211 | -2.8% | 0.4% | 0.5% |
| forward cubic8 | 1 | 3.145 | 3.149 | +0.1% | 1.261 | 1.239 | -1.8% | 0.5% | 0.6% |
| reverse cubic1 | 1 | 3.233 | 3.285 | +1.6% | 1.078 | 1.038 | -3.7% | 1.4% | 1.7% |
| reverse cubic8 | 1 | 3.226 | 3.272 | +1.4% | 1.062 | 1.008 | -5.1% | 0.6% | 9.7% |

Read: CPU per Gbit is lower in every cell (-1.8% to -5.1%), beyond the A/A gap except reverse 8 flows
(gap 9.7% on CPU); Gbit/s is unchanged forward and +1.4..1.6% reverse. J1204's two holds on the same patch
gave -1.6/-2.8% forward, -1.5/-0.2% reverse.
