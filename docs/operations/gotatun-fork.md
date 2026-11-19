<!-- How infraternal's GotaTun fork follows upstream and carries our patches (#260, D169, D289, D340). -->
# GotaTun fork: following upstream

infraternal's mesh engine is GotaTun (D169), built from our fork and pinned by
commit in `crates/plugins/mesh/Cargo.toml`. The owner wants the fork to stay
current with upstream, and our patches to keep working as upstream changes are
pulled in periodically (2026-11-15, #260). This page describes how that works.

## Repositories

| remote | URL | role |
|---|---|---|
| `upstream` | <https://github.com/mullvad/gotatun> | upstream GotaTun; we only read it |
| `github` | <https://github.com/kaygdotorg/gotatun> | product pin source; orchestrator mirrors job branches |
| `origin` | <https://git.kayg.org/kayg/gotatun-fork> | job branch destination (D340) |

Jobs push fork branches to Forgejo and confirm them with `git ls-remote`.
The orchestrator mirrors the exact commit to GitHub; jobs never push the GitHub
remote. Both copies are required before the shipping pin can land. GitHub refuses pushes that
add commits changing `.github/workflows/*` unless the pushing token has the
`workflow` scope. Upstream commits often change CI, so the credential that
pushes sync branches to GitHub needs that scope.

## Branch model

- **Sync branches** `infraternal/upstream-YYYYMMDD` (or job branches
  `jNNN-upstream-YYYYMMDD` selected with `--branch`) hold upstream `main` as of
  that day plus our patch series on top, as a linear list of commits. Once
  pushed, a sync branch is never rewritten. It may only fast-forward, for
  example when a fix is appended before the branch is pinned. Old pins and
  other jobs' branches point at its commits.
- **The series** is whatever the product pins, minus upstream:
  `merge-base(pin, upstream/main)..pin`. Because landed patches move the pin
  beyond a sync branch's tip, the next sync starts from the pin, not from the
  last sync branch.
- **Experiment branches** (`jNNN-*`) start from the current pin and are never
  rewritten either. To carry one onto a newer base, make a new branch (see
  below).

## Writing patches that keep rebasing cleanly

Every commit in the series is replayed onto each new upstream. These rules keep
that cheap:

1. **One purpose per commit**, with a message that says what changed, why, and
   which alternatives were rejected (CLAUDE.md "History and tracking"). WIP
   commits, fix-ups and revert pairs are folded or dropped before a commit
   reaches the pin. A revert pair costs a conflict resolution twice and
   documents nothing the message of the kept commit can't.
2. **No merge commits.** The series must stay linear, and the sync script
   refuses merges.
3. **New code in new files.** Put a feature in its own module (as
   `device/parallel_crypto.rs`, `tun/tun_async_device/tso.rs` and `gso.rs`
   do) and keep edits to upstream files to the smallest hook: a call, a
   field, an import. Upstream's hot files (`device/mod.rs`, `udp/buffer.rs`)
   are where conflicts happen.
4. **Don't reformat upstream code**, rename upstream items or move them. Run
   `cargo fmt` only on what you wrote. Every changed upstream line is a future
   conflict.
5. **Respect upstream's crate boundaries.** Packet parsing lives in
   `gotatun-packet` and AEAD in `gotatun-crypto`. Their private modules (for
   example `gotatun-packet`'s `util`) are reached through the crate-root
   re-exports. Process-wide concerns such as calling into the C allocator stay
   in `gotatun`.
6. **Tests travel with their change**, in the same commit or the one just
   before it (red first).
7. **Upstreamable fixes stand alone**: no dependency on our features, and a
   message an upstream maintainer can read. They are good candidates to offer
   upstream, which removes them from our series for good.
8. **Bench and harness files** (such as `j88i-r4b-overlay/`) stay in their own
   directory and their own commit at the end, so they never conflict.

## Cadence and current series

Check upstream every working day and before starting a new fork patch. When
upstream advances, prepare a sync that day; complete the tests and measurements
before integration. This is a maintenance routine, not an installed timer.
The orchestrator owns checking and scheduling the job, so an unattended fetch
never changes the product pin or publishes an unreviewed rebase.

The daily check, from an infraternal checkout at current `origin/dev`, is:

```sh
scripts/gotatun-upstream-sync sync --fork ~/Developer/Worktrees/gotatun-sync --check
```

On 2026-11-18 upstream still points to `e95ba9693c15c9063a8c0293d9cbc67aef15eb1d`
(0.10.3), the same upstream base J741 fetched on 2026-11-15. The product's
`72dc734` pin still uses 0.10.2. J875 reconstructs the full current series from
J741's cleaned/adapted `bba3dcf` plus all 36 later commits `9d7c3ff..72dc734`:
85 commits above upstream, including the ring-backend repair. This avoids
replaying the old 108-commit WIP/revert history. The fork branch is
`j875-upstream-20261118`; #260 records its exact tested head and receipts.
J870's concurrent ECN series remains separate and must be carried onto the
qualified sync in a new branch, then tested and measured again.

## Syncing with upstream

`scripts/gotatun-upstream-sync` does the mechanical part. Keep one long-lived
fork checkout for it, because `rerere` remembers conflict resolutions in that
checkout's `.git/rr-cache` and replays them on the next run.

1. **Rebase (control host, git only).**

   ```sh
   scripts/gotatun-upstream-sync sync --fork ~/Developer/Worktrees/gotatun-sync \
     --branch jNNN-upstream-YYYYMMDD --keep-conflict
   ```

   It fetches `upstream` and `origin`, prints how far the pin is behind and
   which upstream commits touch the files our series changes, then creates
   `infraternal/upstream-<today>`. On a conflict it names our commit, the
   files and the upstream commits behind them, aborts, and exits 3. Rerun with
   `--keep-conflict` to resolve by hand. Keep upstream's design and re-express
   our change in it. If upstream made one of our commits unnecessary, drop it
   (`git rebase --skip`) and say so in the next commit's message. Then add a
   short "Rebased onto upstream X" paragraph to every commit whose code had to
   change.
2. **Test (a build VM, through build-slot).** Copy the branch there (a git
   bundle is fine), then:

   ```sh
   ~/infraternal-ops/build-slot nix develop <fork> -c env CARGO_TARGET_DIR=<target> \
     <infraternal>/scripts/gotatun-upstream-sync test --fork <fork>
   ```

   This runs the D289 check that the `device,ring` build pulls in no aws-lc-rs,
   then rustfmt, clippy with warnings denied, the product feature check, and
   the workspace tests with `ring` and with all features. Also check that every
   commit builds on its own (`cargo check --locked --workspace --all-targets
   --all-features` per commit). Compare the test counts with the old pin's;
   tests that upstream moved between crates still count.
3. **Push** to Forgejo from the control host, confirm the SHA with
   `git ls-remote origin refs/heads/<branch>`, and ask the orchestrator to
   mirror that exact SHA. Keep the shipping pin URL on GitHub. A missing
   workflow scope blocks integration; use an unpushed scratch commit for
   temporary local/Forgejo product-gate inputs, as authorized by the
   orchestrator. Never relax cargo-deny source policy to bypass the mirror.
4. **Bump the pin** on a scratch infraternal branch. These four places move
   together:
   - `crates/plugins/mesh/Cargo.toml`: `rev`, and `version` when upstream
     released;
   - `Cargo.lock`: run `cargo update -p gotatun`, then revert hunks it makes
     to unrelated packages (it tends to rewrite `windows-sys` versions);
   - `nix/package.nix` `outputHashes."gotatun-<version>"`: the key follows the
     version. The hash is `nix run nixpkgs#nix-prefetch-git -- --quiet --url
     <fork URL> --rev <rev> | jq -r .hash`. One entry covers every crate from
     that commit;
   - `THIRD_PARTY_NOTICES.md`: the commit and URL.

   Run `scripts/verify quick`, then `scripts/verify fast`, on a build VM through
   `build-slot`, with a fresh job target and a short private 0700 TMPDIR passed
   inside `nix develop`. Also run the native Mac mesh library tests under
   `lockf -k /tmp/mac-bench.lock`, with `CARGO_INCREMENTAL=0`, and remove the
   Mac target before releasing the lock.
5. **Perf A/B** on backup01 against the current pin, with the fair kit. Build
   both CLI arms (`cargo build --release -p gotatun-cli --no-default-features
   --features ring`) in one checkout on one host. Check the crypto backend of
   each binary. Run counterbalanced holds (ABBA/BAAB) at 8 flows for both cubic and BBR, three holds each (J875 minimum), and
   compare Gbit/s, CPU/Gbit, loaded p99 and RSS. There must be no regression
   beyond the noise floor, or the regression must be explained.
6. **The orchestrator merges** the pin bump once the gate and the A/B pass.

## Carrying experiment branches onto a new base

An experiment based on the old pin `P` moves to the new sync branch `S` as a
new branch. The original is left alone:

```sh
git checkout -b jNNN-<name>-on-upstream-YYYYMMDD origin/jNNN-<name>
git rebase --onto origin/infraternal/upstream-YYYYMMDD P
```

Conflicts here come from upstream's changes, not from the series, so resolve
them the same way as in a sync. Re-measure the experiment on the new base
before its numbers count: upstream's changes are under it now.

## What proves our patches still work

A rebase that applies only proves text compatibility. For each sync, #260 must
record the old/new upstream and fork SHAs, the complete upstream commit list,
each conflict and dropped patch, and a range-diff of the carried series.
Compare test counts across the packet/crypto crate split and explain changes.
Run the script's feature matrix, including a successful dependency-graph check
that proves the product's ring build excludes aws-lc-rs. Preserve the receive
ordering, filtering, small-packet lanes, TUN buffering, socket ownership,
per-family Mac binds and connected-send-off regression tests. The native Mac
run is required because Linux cannot exercise those socket invariants.

The product quick/fast gate and native Mac mesh tests must use the exact new
pin. Retain complete logs, gate table and EXIT line outside the checkout and
post their paths on #260. Perf receipts must identify both binary hashes and
source SHAs, congestion control, flow count, hold order, throughput, CPU/Gbit,
loaded p99, RSS, lost probes, and successful restoration. Explain regressions
beyond the measured noise floor and seek the owner's decision where required.
Only the orchestrator integrates after GitHub has the exact tested fork SHA;
there is no claim of completion from a clean rebase or green fork tests alone.
