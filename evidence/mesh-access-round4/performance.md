<!-- Final locked-VM measurements for precise connection-state retirement, D242 and #173. -->
# Final measurements

The final node code is a707640f; the corrected probe is 39e70f8b. Baseline node
code is 023aee89 after the required dev merge, before this round's implementation.
Both node candidates are release builds with identical profiles. The coordinator
fixture is a dev build; its artifact is qualified separately. Source, adapted
and executable-segment hashes are in the artifact JSON files. Packaging changes
only the private loader/search paths and debug sections.

The campaign ran on `infraternal-perf-test`, kernel `6.12.69+deb13-amd64`, four
CPUs, through the authorized NetBird connection, shared lock and CPU-weight
scope. All numbers below come from that VM. Raw samples record load at each
observation. Change cases had one-minute load between 0.46 and 1.80.

## Change to last node refusing

Each cell is milliseconds from the coordinator change request to the last of
two live receiving nodes completing final installation and exact retirement.
This is a conservative upper bound beginning before the writer commits, rather
than a timestamp inside COMMIT. Every case streams TCP and UDP in both families,
verifies service reach before the change and verifies that no packet initiated
after its node's final apply reached that service. Sender filtering is disabled
after apply to expose late receivers; sender enforcement is checked separately
by the 344 functional assertions. The 150 ms case applies half-RTT delays to
control delivery/ACK and validates the actual data-link RTT with ping.

| Backend / change | 10 peers, local | 10 peers, 150 ms RTT | 1,000 peers, local | 1,000 peers, 150 ms RTT |
| --- | ---: | ---: | ---: | ---: |
| nft / rule removal | 113.49 | 163.05 | 205.92 | 291.78 |
| nft / peer retirement | 85.60 | 137.61 | 169.83 | 261.84 |
| nft / default tightening | 94.80 | 125.17 | 1363.54 | 6369.69 |
| iptables-nft / rule removal | 285.43 | 329.45 | 394.03 | 446.09 |
| iptables-nft / peer retirement | 422.49 | 462.19 | 460.46 | 523.27 |
| iptables-nft / default tightening | 313.74 | 351.34 | 1257.02 | 6399.34 |

The 1,000-peer default-tightening case takes about 6.4 seconds at 150 ms RTT.
The final kernel applies are recorded separately in
`default-tightening-publication.json`; changing every effective peer rule uses
the existing chunked delivery/ACK path. The observed end-to-end delay is retained
as a finding, without changing that frozen transport contract in this repair.

Each node has the stated number of actual kernel peers, including synthetic
public keys. There are three live nodes and two receiving nodes. These results
do not model 1,000 concurrent coordinator workers or 1,000 live traffic pairs.
The trusted coordinator fixture uses production writers, migrated SQLite and
publication, without an authenticated HTTP ceremony.

## Apply comparison

Balanced base/head/head/base cohorts each execute 12 narrow/widen rounds on two
nodes: 96 per-node samples per candidate and configuration. The table reports
median milliseconds. Individual narrow/widen medians and p95 values are retained
in `performance-summary.json`. All four combined medians improve. The access-only
path checks routes and installed keys before using one final firewall transaction;
peer/address changes retain the replacement fence. This avoids an unnecessary
intermediate transaction while retaining exact retirement. These ephemeral node
fixtures omit public-journal I/O in both candidates; persistence correctness is
covered by the separate stateful failure/recovery proofs.

| Backend | Peers/node | Baseline median | Final median | Change |
| --- | ---: | ---: | ---: | ---: |
| nft | 10 | 61.47 | 31.25 | -49.2% |
| nft | 1,000 | 94.63 | 62.21 | -34.3% |
| iptables-nft | 10 | 381.57 | 203.46 | -46.7% |
| iptables-nft | 1,000 | 393.39 | 203.95 | -48.2% |

## Memory qualification

RSS includes the disposable node fixture and its private native libraries; it
is not the full infraternal agent. The projection multiplies the largest sampled
fixture RSS by 1,000 separate nodes; shared pages make it conservative. The
debug coordinator is measured with only three live workers, so its value cannot
be extrapolated to 1,000 workers.

| Peers/node | Largest node fixture RSS | × 1,000 node fixtures | Three-worker coordinator RSS |
| --- | ---: | ---: | ---: |
| 10 | 6.15 MiB | 6.00 GiB | 12.34 MiB |
| 1,000 | 8.05 MiB | 7.86 GiB | 26.01 MiB |

`final/results-final-fixed/` contains all raw frames, arrival timestamps, calibrated
RTTs and balanced apply samples. `final-fixed-perf-campaign.log` records 39/40 passing cases. The remaining
peer-retirement case is retained with its expected ENOKEY echo error;
`final-recheck/results-peer-recheck.log` records its passing recheck against
the unchanged node binary. Together all 24 change cases and 16 apply cohorts pass. Historical campaigns remain qualified separately in the index.
