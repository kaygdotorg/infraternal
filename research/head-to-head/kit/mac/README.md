<!-- Role: how to run the Mac<->Linux head-to-head windows from this checkout (#260, J674). -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Mac head-to-head windows

The Mac VM (`infraternal-macos-01-std`) and an arm64 Linux VM share one bridge. Each window
runs every engine once: GotaTun pin (`pin`), GotaTun candidate (`cand`), Tailscale and NetBird
userspace, in both directions (`mac-tx`: Mac sends, `mac-rx`: Linux sends) at 1 and 8 flows.
`REPEAT=N` repeats the whole design with unique window ids (`<run>-w1…`); the report refuses a window listed twice.
Run from a fresh checkout of dev; never from a hand-edited copy (owner rule: latest code).

| file | role |
|---|---|
| `mac-window.sh` | one window, run as `lume` under `lockf -k /tmp/mac-bench.lock` |
| `mac-run.sh` | the counterbalanced run: one window per Williams order, lock per window, then the report |
| `mac_pool.py` | `orders` (Williams design) and `report` (pooled, per-window ratios to the baseline) |
| `build-harness.sh` | builds the pin and candidate Mac harness from this checkout (`harness <name> [<gotatun-rev>]`), and `j421net` from `../../tools/j421net` |
| `check-pins.sh` | refuses a window whose Tailscale/NetBird version differs from `pins.txt` |
| `swap-gotatun-rev.sh` | candidate rev swap; fails unless `Cargo.lock` moved only in gotatun |
| `extra-env.sh` | quotes `PIN_ENV`/`CAND_ENV` into the harness's root-only env file |
| `lnx-side.sh` | the Linux peer's helper; copy it to `/opt/j461c/lnx-side.sh` on the peer after a change |

## Prerequisites

- `$KIT_HOME` (default `/Users/Shared/h2h-mac`) with `bin/`: `j421net`, the harness binaries
  (`mesh-bench-pin`, `mesh-bench-cand`; override with `PIN_BIN`/`CAND_BIN`), `tailscale`,
  `tailscaled`, `netbird`: built by `build-harness.sh daemons` from the source tags pinned in
  `../../pins.txt`; `mac-window.sh` runs `check-pins.sh` first and refuses (exit 4) when an installed
  client reports another version.
- The harness test `macos_node::tests::mac_bench_device` is in `macos_node/tests.rs` of this checkout.
  Build both binaries from the checkout itself, under the Mac lock (the Mac disk is small: one
  build at a time, the script deletes its target): `build-harness.sh harness mesh-bench-pin`
  (the GotaTun in Cargo.lock, `--locked`) and `build-harness.sh harness mesh-bench-cand <gotatun-rev>`
  (the same checkout with only the GotaTun rev replaced). Record the printed `BUILD_KIT_COMMIT`
  and lock line in the issue. Never run a binary built from another tree.
- The Linux peer has `/opt/j461c/{lnx-side.sh,bin/*}` (gotatun, headscale, netbird-server,
  tailscale(d), netbird, j421net).

## Run

```
# as lume on the Mac VM, from the checkout:
PEER=192.168.64.7 PSSH=claude@192.168.64.7 bash research/head-to-head/kit/mac/mac-run.sh h2h-r1 pin cand tailscale netbird
SMOKE=1 PEER=… PSSH=… bash …/mac-run.sh smoke pin cand tailscale netbird   # one 5 s window, functional only
```

## Privacy and sudo

macOS Local Network privacy blocks LAN traffic from a non-root, ssh-launched process. Every
ping, probe, sink, source and echo on the Mac therefore runs under `sudo`
(`test_mac_window.py` checks it). Keys never go in argv: the harness reads a root-only env file.
Never touch lume's keychain or the TCC database; the Mac lock is the only lock.

## Not ported (yet)

The WAN row (dummynet loss and delay), the diagnostics samplers (dtrace, `sample`, tcpdump) and
the per-experiment harness variants stay out: add them when a measurement needs them.
Smoke windows are functional evidence only; compare nothing from them.
