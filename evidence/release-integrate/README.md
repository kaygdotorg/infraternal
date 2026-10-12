<!-- Records merge compatibility and verification receipts for #157 (D16, D198, D201, D202, D224-D226). -->
# Release integration into mesh dev

Merge sources: dev `378b97da` and reviewed release `8a26a73b`. The integration
branch is `dev-merge-rp`; only that branch is pushed. Final head and the full
branch-head fast gate, including both static sizes, are recorded on #157.
No deployment, live publication, signing request or external host was used.

## Compatibility

- Keep dev's infraternal agent, mesh engine and mesh plugin byte-for-byte.
  Their existing shipping-scale evidence remains under `evidence/mesh-integrate`;
  this merge makes no new latency, RSS or WAN capacity claim. #173 policy
  repairs remain on their separate branch and are outside this merge.
- Keep node-channel/admission metadata alongside the stamped release identity,
  every server plugin registration, enrollment test and all 21 fuzz targets.
- Keep immutable dev migration `0020_mesh_dataplane.sql`; renumber the undeployed
  release settings migration to `0021_release_channel.sql` and its CLI fixture.
- Keep all 375 registry package/version/source entries unchanged. The lock adds
  the release workspace package (nine dependencies) and four dependency edges
  in existing packages: CLI release/SQLx, fuzz release and server release.
- Adapt release-owned channel/latest declarations to dev's generated command
  tree, shared pretty renderer and versioned JSON envelope. Raw release results
  live under `data.release`. Preserve TTY/--yes edge confirmation, feature-off
  refusal, existing private storage checks and absence-of-server refusal.
  Hosted action IDs and spaced command paths generate identical skills.
- Forward API `socket-host` only from release's `server` feature. Isolated
  server test compilation first failed with missing `Plugin`, `ReplySender`
  and `fresh_session_tx`; workspace feature unification had hidden this.
  Pure metadata and isolated server tests now pass. Do not enable async
  dependencies in the API's default feature set.
- Move the incoming round-two root report unchanged to
  `evidence/release-pipeline-round2/repair-handoff.md`.

The merge retains incoming `4b2cd2ad` baseline changes in history. Its required
separate follow-up restores **exactly** dev's verifier and PROCESS wording:
16,142,672/13,555,672-byte baselines with the unchanged 262,144-byte allowance.
The baseline raise is an open owner question, not decided by this integration.
No other gate or release-profile change is made.

## Verification

Native runtime tests reuse dev's recorded local optimization: opt-level 1 only
for infraternal, infraternal-agent and infraternal-plugin-api. Dependency and
release profiles are unchanged. This is a qualified runtime-profile result,
not a claim that the unoptimized workspace RSS gate passed. The separate
`clippy-final.log` is a default-profile workspace Clippy pass.

- Touched Rust suites pass; server: **310 passed, 37 ignored**.
- Rebuilt CLI unit suite: **65 passed**. Compiled CLI fixture: **1 passed**;
  stable default, no/yes TTY confirmation, explicit --yes, disable, absent
  server, both skill syntaxes and `0.1.0 (stable)` version all checked.
- Standalone release: **7 unit tests passed**, R4/R5 integration tests passed.
  R4: two abrupt stops each leave one **65,536-byte** stage; restart leaves
  **0 bytes**. R5: **8 writers/8 pool slots**, **7 idle**, control/authority
  reads succeed; authority read **2 ms**. These are local fixture measurements,
  not production TLS, terminal or fleet latency claims.
- All **21 fuzz bins**, including optional mesh-node, pass
  `(cd fuzz && cargo check --locked --bins --all-features)`.
- Tracer check and source tests: **151 passed, 10,922 assertions**.
  Weighted broader frontend suite: **158 passed**. Protocol: **36 passed,
  34,462 assertions**, using a separate oracle target to avoid Cargo lock waits.
- Production transfer: critical gzip **291,675/307,200**, Brotli
  **242,435/256,000**; deferred **49,651/51,200**, **43,753/45,056**;
  largest on-demand chunk **15,066/20,480**, **13,397/18,432** bytes.
- Local release Python **5 passed**; Bun **5 passed, 21 assertions**.

Keep the first failures: unweighted broader frontend recovery rotation timed
out at its unchanged 5 s deadline; weighted rerun passed all 158 tests. The
first CLI fixture expected the wrong shared renderer header (Details instead
of Release); corrected fixture passes without changing presentation. Initial
Clippy found an owned-value clone in the adapter; direct move into the result
map preserves output and passes lint. No timeout/assertion loosening or #118
baseline exemption was used. The initial unweighted native compile was stopped
and restarted in the weighted scope; it was not a completed gate result.

The full TS dispatcher stopped after its completed bundle checks so the oracle
could run separately; `protocol-tests.log` completes that proof. Final fast
verification is run on the restored-baseline branch head and quoted verbatim
on #157. Static size failure against those old ceilings is expected. The
independent release R6 P3 restrictive-umask finding remains for fix-forward.

## Author review

Checked the release operation checklist, plugin/SSH contracts and both commit
histories. Trust/download/cleanup/authority implementations retain reviewed
release behavior; mesh lifecycle and data-plane implementations retain dev.
Schemas remain additive, migrations preserve existing numbers/checksums,
private operator commands never create a server, pure/build-disabled roles
remain removable, and no new foundational dependency is selected. The API
feature seam has both red and green compiler/test receipts. This author check
is not a substitute for the orchestrator's integration review.
