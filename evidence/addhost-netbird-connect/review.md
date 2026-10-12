<!-- Root cause, scope and author security checklist for the add-host connect regression (#195). -->
# Connect regression

Release 4 (3aec316e) sent `CHECK_SCRIPT`. Source-contract git bisect identifies 436dfb9723e2f17161c8b2a1e6af2fa9cff7d3de. This commit changed
`Bootstrap::run` to send `previous_attempt::check_script(mode)` or the
cleanup-owned clear variant. `auth_order::Pending::run` still required exact
`CHECK_SCRIPT`. The failure occurs locally before calling `automatic`, so no
SSH connection, authentication, channel, environment or shell negotiation can
cause this particular production failure. `Failure::at(Connect)` overwrites
the static rejection with generic connection advice and has no child status.

The earlier auth-order tests supplied only `CHECK_SCRIPT`, while installation
tests used a controlled transport that bypassed the `Pending` adapter. Neither
tested bootstrap's generated first command through automatic authentication.
`tests/mesh_ssh.rs` now sends that production command through `AutoAuth` and the
real SSH transport; `tests/auth_order.rs` covers both ownership modes during
fallback. This is the missing composition regression that would have caught it.

The integration fixture uses NetBird v0.79.0's actual server engine versions:
[server configuration](https://github.com/netbirdio/netbird/blob/v0.79.0/client/ssh/server/server.go)
and [dependencies](https://github.com/netbirdio/netbird/blob/v0.79.0/go.mod).
The fixture mirrors none authentication and the Ed25519 host signer, runs
loopback-only and executes checks with a disposable HOME. It exercises the
production SSH plugin and automatic-auth adapter, without launching enrollment
or any installation. The production server is built by the full static gate.

`regression-before.txt` records the exact rejected initial command on the
unmodified release-5 plugin. `trace.txt` independently demonstrates none auth,
compatible algorithms and mux-channel execution on the pinned fixture.
The build-host probe reached 10.69.69.52 and observed its stated banner and
compatible SSH algorithms, then stopped at strict host-key refusal. No remote
key was accepted and no remote command or host write was performed.

The fix admits only four exact generated read-only variants: the old check,
rootless and root ownership checks, and the cleanup-owned clear record.
No prefix check or arbitrary stdin is admitted. Fallback repeats the selected
fixed check; there is no extra round trip, engine change or persistent task.
All signing/password-provider methods panic if reached in the integration test.
Connection counts establish reuse; no local timing is performance evidence.

The continuation expands each of the three real-engine checks over NetBird,
Tailscale and absent inventory metadata (typed hosts): nine checks use nine
physical connections, request zero later credentials, and refuse a changed pin.
This exercises both provider metadata values through the shared network-auth
path, not a deployed Tailscale server. Root and rootless ownership variants are
also covered by the controlled authentication fallback tests.

# Author checklist

- D181/D183: production OpenSSH retained; only test-engine dependencies added.
- D182: strict checking and pin publication unchanged; changed public pin is
  rejected and its bytes remain unchanged in the real-engine regression.
- Credential fallback: exact checks and empty stdin only; appended writes are
  rejected, both root/rootless fallback paths are covered.
- Ownership inspection: fixed generated code only; it reads existing receipts
  and locks existing directories without creating files. No setup writes.
- Diagnostics: WARN contains only public coordinates, numeric status, mode and
  classified failure kind. Arbitrary host output and secrets stay withheld.
  Static diagnostic markers reuse the bounded tail; Failure does not gain a
  field or grow each retained event.
- UI: existing shared wizard materials and controls reused. Connect has one
  failure sentence and actionable next text. Details deduplicate text shown
  above them. Production-build screenshots are for independent visual review;
  no author visual-quality verdict or physical-iPhone claim.
- No new parser or production dependency. Existing fuzz targets remain.
- Worktree only; no owner live state changes, deployment or host-key edits.

Continuation fixes the empty-Details fallback after its browser assertion fails,
and adds the server WARN field after its sentinel assertion fails without it.
The production-base native gate also needed a test-only module guard and an
assertion consuming the initial replay-complete event before live output. These
repairs alter test compilation/assertions only, not infraternal agent behavior.
Screenshots come from the production tracer at 1440x900 and 393x852; functional
tests on the build host do not establish timing budgets or physical-iPhone behavior.

The test Go toolchain was obtained with `nix shell nixpkgs#go` (Go 1.26.8).
That fetched a Nix-store toolchain rather than installing it under HOME as the
job requested. No Nix-store deletion was attempted because it is shared. Go
build/module caches and all fixture artifacts are under this job's scratch.
