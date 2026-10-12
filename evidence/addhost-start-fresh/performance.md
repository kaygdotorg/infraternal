<!-- Booked perf-VM checker and transient lease measurements for #169. -->
# Setup check measurements

Only `infraternal-perf-test` (10.69.69.208, Linux, 4 cores), through NetBird SSH,
under `/var/lock/perf-bench.lock`. Raw final data: `perf-check-final-source.log`; harness:
`perf-check.py`. Inputs are the shipped fixed check and ownership shell. No CPU
load generators or other hosts. Initial load 0.03/0.01/0.00; final 0.18/0.04/0.01.

101 paired clean-host samples after ten warmups, alternating run order:

| Check | Median, ms | p99, ms |
| --- | ---: | ---: |
| Prior fixed check | 22.935 | 28.408 |
| Same check plus ownership classification | 27.431 | 32.940 |

Paired median addition 4.438 ms, maximum 10.366 ms; **zero additional SSH round
trips**. Stale marker + inode-bound journal + closed real Unix socket: 31 samples,
median 74.745 ms, p99 89.545 ms. The earlier shell-per-link traversal was replaced
with one bounded native traversal; its retained exploratory measurements are
superseded by this final-source run. These measure the checker, not complete
network provisioning or browser perception; earlier round-three network setup
measurements remain separate and are not presented as a controlled comparison.

At 1,600 checks, unrounded paired median addition × count is 7,100.142 ms of serial check
work; global concurrency remains eight. This is arithmetic, not a measured
1,600-host wall-clock result. One temporary setup lease is 1,908 KiB RSS × eight
concurrent hosts = 15,264 KiB. It has a 180-second ceiling and no periodic work;
live-lease refusal and retirement pass on the VM. No daemon steady-state worker
is added. No browser, full-setup speedup or physical-iPhone timing claim.

The initial VM fixture exceeded Unix `sun_path`; relative binding fixed only the
fixture. That failed run is retained in `perf-check-first.log`. Final source
hashes are recorded with the gate artifacts. All later RTT self-tests use the
unchanged three-sample repository gate forwarded to the same locked VM by
`rt-timing-gate-wrapper.py`; other scripts keep the normal Nix Python interpreter.

A separate real NetBird SSH command-gap check holds the same shared lock and
confirms that the lease survives closure of the first SSH command, then retires
the exact lease through a second command. Both functional assertions pass;
`real-ssh-gap.log`. No timing is taken on the build host.
