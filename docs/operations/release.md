<!-- Operator contract for immutable signed releases and architecture-specific bootstrap payloads [184,213,220,224,225,226]. -->
# Signed releases

Stable releases use the workspace `x.y.z` version in `Cargo.toml`. Edge releases
use `edge-YYYYMMDDTHHMMSSZ`, stamped from UTC at build time [226]. The public bucket
contains `releases/<version>/infraternal-{x86_64,aarch64}-musl`, the initial-shell
`infraternal-{x86_64,aarch64}-session-musl` images, the server
`infraternal` copy, `VERSION`, `SHA256SUMS`, `SHA256SUMS.sig`, `releases/index.json`, and `releases/channels/<channel>.json`.
The release-signer Worker hashes R2 objects itself, signs the manifest and adds
the index entry and channel pointer. The pipeline never holds the signing private key [224]. The signed `VERSION`
file contains the build version followed by a newline. The channel comes from
that signed version, never from a separate unsigned metadata field. `infraternal
--version` shows the version and channel. Both the downloader
and public verification compare it with the requested version: the signature
on SHA256SUMS alone does not authenticate the URL and cannot prevent replay
of a valid older release under another version path.

Build on Linux with the pinned Rust toolchain and both musl targets installed:

```sh
export CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/release-pipeline/target"
scripts/release/build --channel edge
```

This reuses `scripts/package-release`, `.cargo/musl-{cc,ar}.sh` and
`scripts/auth-toolchain` (checksum-pinned Zig 0.15.2 [213]). It produces the
complete immutable bundle in `$CARGO_TARGET_DIR/releases/<version>`. New
publication requires both host images and both session images before network
work begins. Every image is uploaded and included in the signer-generated
checksums. Public verification still accepts older signed releases without
session images; an advertised session image must be present and match its
signed digest.

The Linux host images include the Mesh node, so Add host can enroll a node
with Mesh traffic available after the coordinator assigns its addresses and
peers. Linux Mesh enrollment state belongs to its original machine ID. A
backup of that state can restore the same enrollment on the original
installation. Another installation must enroll through Add host.
The macOS host built by `scripts/macos-release` carries the Mesh node too
(`remote,desktop,plugin-mesh`, #221) and follows the same enrollment rules.
The build requires `--channel`; there is no default. Use `--channel stable`
for the workspace version. Both architecture binaries and signed `VERSION`
carry the same stamped identity.
The build marks the binaries as release builds: missing public releases and
verification failures cannot enable the development fallback.

## The macOS binary (#483)

A release can also carry `infraternal-aarch64-darwin`. That is the
default-feature `infraternal` for Apple silicon Macs, which a Mac runs with
`infraternal up <server>`. Linux cannot link it: its native dependencies need
the Apple SDK and `/usr/bin/clang` (#379). So it is built first, on the Mac,
and then handed to the Linux build:

```sh
# On the Mac build machine, in the repository's nix shell:
nix develop -c scripts/release/build-darwin --channel edge /Users/Shared/release-darwin
# Copy that directory to the Linux release builder, then:
scripts/release/build --channel edge --darwin /path/to/release-darwin
```

`build-darwin` stamps a new edge version, or the workspace version for
`stable`, and checks that the binary links only libraries macOS ships. It signs
the binary ad hoc with the hardened runtime: no identity and no timestamp, so
a rebuild of the same tree signs to the same bytes. `BUILD-INFO` records the
source, toolchain, SDK, size and digest. `build --darwin` takes the release
version from that directory's `VERSION`, so the Linux and Mac binaries carry
one identity. It refuses a binary that is not arm64 Mach-O, or that lacks that
version string. The binary goes into `SHA256SUMS`, and `publish` uploads it,
so the signer covers it like every other payload. No other key is involved.
The Mac binary is optional: a bundle built without `--darwin` is Linux-only,
as before. When a signed manifest lists it, verification downloads it and
checks its digest. Intel Macs have no binary.

People install it by hand for now, which the one-command join (D311) will
replace:

```sh
v=<version>; b=https://builds.infraternal.com/releases/$v
curl -fsSLO "$b/SHA256SUMS" -O "$b/SHA256SUMS.sig" -O "$b/infraternal-aarch64-darwin"
ssh-keygen -Y verify -f allowed_signers -I release@infraternal.com -n infraternal-release -s SHA256SUMS.sig < SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS
chmod +x infraternal-aarch64-darwin && ./infraternal-aarch64-darwin up https://<server>
```

`allowed_signers` is `release/allowed_signers` from this repository.

The orchestrator supplies `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` and
`RELEASE_CALLER_TOKEN` in the publishing process environment, then runs:

```sh
scripts/release/publish <version>
```

Do not put tokens in shell arguments, checked-in environment files or logs.
Authorization is passed to curl through its configuration stdin; the scripts
never print tokens or write them to files. The uploader needs R2 object access,
without Worker edit access. Only the owner may change/deploy the signer [224].
Every authenticated and public request includes a User-Agent.

Publication refuses an existing object or signed release. It uploads the whole
bundle, asks the Worker to sign, downloads the manifest, signature and payloads,
and verifies the signature and all hashes before reporting success. Interrupted
publication leaves an immutable partial release; investigate it rather than
repeating uploads over existing objects. The uploader checks the authoritative R2 object prefix, including partial or
unrelated objects, and holds a nonblocking `flock` for the entire publication,
including signing and public verification. The fixed per-user lock path is
`${XDG_STATE_HOME:-$HOME/.local/state}/infraternal/release-publish/<version>.lock`,
independent of `CARGO_TARGET_DIR` and the worktree. The state path must be
absolute; the lock directory and file must be owned and private. Lock files
remain in place: unlinking a held lock would allow a second writer to lock a
new inode. The kernel releases the lock when its last descriptor closes;
in-flight child requests retain it after an abrupt publisher stop. PUTs also send
`If-None-Match: *` as a precaution. The REST upload reference does not promise
conditional-write semantics, so the orchestrator must serialize publishers
across machines; the preflight is not a distributed lock. See the official
[object list](https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/objects/methods/list/)
and [upload](https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/objects/methods/upload/)
API definitions. Storage listing/upload JSON and Worker replies are bounded
and reject duplicate fields recursively, including nested objects. An
ambiguous response stops publication with a plain reason; no provider
diagnostics are echoed. This pipeline does not consume `releases/index.json`.

For an edge publication, take the version from the completed bundle's directory
name, then publish and verify that exact version:

```sh
scripts/release/publish edge-20261011T071500Z
scripts/release/verify edge-20261011T071500Z
```

Replace the example timestamp with the build's actual UTC stamp. Both scripts
accept only `x.y.z` or `edge-YYYYMMDDTHHMMSSZ`; prerelease suffixes are refused.

Anyone can verify a published release, without credentials:

```sh
scripts/release/verify 0.1.0
```

Both public trust anchors are in `release/allowed_signers`, compiled into the
binary using `include_str!`. The signature has Ed25519 algorithm, SHA-512
message hash and namespace `infraternal-release`. Local manual verification is:

```sh
ssh-keygen -Y verify -f release/allowed_signers -I release@infraternal.com \
  -n infraternal-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum --strict --check SHA256SUMS
printf '%s\n' '0.1.0' | cmp - VERSION
```

The checksum command requires the named payloads beside the manifest. Use
the expected version in the `printf` comparison.

# Server release channel

Only edge builds are being published for now. A stable server reports `no stable release yet` until a stable release is published, with explicit opt-in instructions.

Every existing server defaults to `stable`, including a server running an edge
binary. The release plugin is removable with the Cargo `release` feature and
switchable at runtime through `plugins.set_enabled`. Plugin construction starts
no work; the server's update check (below) is a separate timer that reads the
plugin's switch and channel before each check.
Its channel is persisted in `plugin_settings.settings` alongside other server
feature settings. Descriptor defaults apply until a setting is explicitly saved.

```sh
infraternal server --data /path/to/existing/private/data channel
infraternal server --data /path/to/existing/private/data channel edge
infraternal server --data /path/to/existing/private/data channel edge --yes
infraternal server --data /path/to/existing/private/data channel stable
infraternal server --data /path/to/existing/private/data release latest --json
infraternal skill release.channel.set
```

Edge builds are published as they are made, unreviewed. Switching to edge
requires typing `yes` on a TTY, or `--yes` for automation. Switching back to
stable needs no confirmation. These local commands open only an existing
private server database and never initialize a server. All support `--json`.
The same declared WebSocket actions are `release.channel.get`,
`release.channel.set` and `release.latest`. Channel writes require owner authority
and a fresh session at the transaction boundary. An edge API request must
include `{"channel":"edge","confirmed":true}`; omitting confirmation or sending
false is refused even if the setting already reads edge.

The latest action fetches only `releases/channels/<selected-channel>.json`.
The pointer is untrusted: its version must match the selected channel grammar,
and that release's manifest, signature and `VERSION` are downloaded and
verified against both embedded keys before returning a verified identity.
A signed VERSION replay from another release is refused. Only metadata is
downloaded by this read-only action; payloads still need their own verification.
No stable release has been published yet. A missing stable pointer reports
“no stable release yet” and the explicit opt-in command, without requesting
edge. Network, invalid pointer and signature failures remain failures.

## Update check and staging (#211 S3)

A root server running a pipeline release build (`INFRATERNAL_RELEASE_BUILD=1`)
checks its channel by itself: about 2 minutes after start, then every 15
minutes ±20 %, doubling after each failed check up to 6 hours. It is one
sleeping timer, so it uses no CPU between checks (D81). Other builds, non-root
servers and non-Linux hosts never start it. Offline or refused checks are
recorded, not logged as warnings.

A check reads the channel pointer and the release's signed metadata. When the
release is strictly newer than the running version and on the same channel,
the server downloads `infraternal-<arch>-musl`, verifies it with the same
verifier as `restart --binary` (signed `SHA256SUMS`, `SHA256SUMS.sig` and
`VERSION`) and keeps it in `<data>/updates/staged/`. The same version does
nothing. An older version or another channel's release is refused; only an
explicit request (a D295 rollback or a channel switch, coming in S4/S5) may
stage one, and never without the signature. Staging needs 192 MiB free
(the 128 MiB image bound plus a 64 MiB reserve) and keeps only one release.
Interrupted downloads are deleted and start over at the next check. Nothing is
applied: switching to a staged release is S4.

A `staged/` folder is never trusted as found. Before any use, at every check and
once when the timer starts, it must be a real directory owned by the server's user
with no group or other access, and its files must pass the same signed-release
verification again. Anything else is removed. A staged release is kept only while
the channel still announces it: when the pointer moves to anything else (a yanked
build, another version, or nothing), the staged release is removed and the state
says why. S4 applies only what `Updater::confirm_staged` returns. That call
re-checks the staged release against the pointer and holds the folder lock until
the switch is done. When the pointer moves on to a *newer* release on the same
channel, the staged release stays until the newer one is downloaded and replaces
it, so a failed download never leaves nothing staged. At apply time such a
release is refused as superseded, not withdrawn, and kept.

Only faults back off: the network, the disk or a failed verification. A
refusal (an older or another channel's release) is recorded as `refused` and
keeps the normal 15-minute pace, and so is "updates are off". An explicit stage
(a D295 rollback or a channel switch) is recorded as `hold`. Periodic checks
leave a held release alone until it is applied or cancelled.

`<data>/updates/` is `0700` and owned by the server's user; `state.json` (0600)
records the running version, channel, newest verified release, staged release,
last and next check, last error, refusal, hold, the last removed release and
why, and the failure count. It lives outside the database so that a D295
database restore does not erase it. Owners read it with the
`release.update.status` action, and the `release.update` topic sends
`{"type":"update","update":{…}}` whenever it changes. The status also has
`mode`, which is `auto` or `off`, and `reason`, which says plainly why updates
are off on this host: not a Linux server, a development build, the server not
running as root, the release plugin switched off, or no valid channel set.

## Applying an update and undoing it (#211 S4)

Where the check runs, the server also applies what it staged, by itself, in a
**quiet window**: nobody has typed into a terminal or attached one for 5 minutes
(D251). No deadline forces it, so an update never interrupts typing. With the
release plugin switched off nothing applies, not even an explicit stage. A
release the channel withdrew, or one it superseded, is never applied.

The switch is the same warm in-memory handoff as `infraternal server … restart
--binary` (D217): one process (the PID stays the same), the CA handed over
unlocked on a private stdin pipe, and live sessions continue in their own shim
processes. If the CA is unlocked when the switch starts, whether by an earlier
handoff or a passkey, the new release must receive it, or the switch is refused
and nothing changes. Like any restart into a named binary, the switch mirrors the
durable mesh identity (`<data>/mesh/`, #489) to the legacy runtime path, so a
previous build finds it too. An undo does not start the previous build without
that mirror.

Before the switch, the server:

1. re-confirms the staged release against the channel (S3) and keeps the folder
   locked until the exec;
2. moves it to `<data>/updates/releases/<version>/` (a rename, so the file that
   was verified is the file that runs; the switch re-checks its signature on a
   sealed copy and never reopens it by path);
3. copies its own image to `updates/previous/` and writes one database copy
   beside it (`VACUUM INTO`, D295);
4. writes `updates/pending.json`, naming both releases by the SHA-256 of their
   images.

**The trial.** The new release has 2 minutes to pass its health check. `/healthz`
must answer 200 on its own listener, a write transaction must commit, and the CA
must be unlocked if it was before. On a pass, `updates/current` (a symlink, the
boot pointer) moves to `releases/<new>`. Other installed releases are removed,
and `previous/` is kept until the next update, so S5's manual roll back can use
it.

**The undo (D295).** If the check fails or times out, or the new release cannot
start serving at all (a failed database migration, for example), the new release
execs the previous image again, warm, and gives it back its own path. Before the database
opens, the previous release puts the database copy back (removing the WAL and
shared-memory files of the database it replaces) and records the update as
`undone`. It also **pauses** that version, so the timer never stages it again.
Data written during the trial is lost, as D295 accepts.

- If the new release crashes or is killed during its trial, the service manager
  starts the boot pointer, which still names the previous release. That start is
  cold (D168): the CA stays locked until a passkey unlocks it. The previous release
  still restores the copy and pauses the new version.
- If the new release cannot even exec, the late-exec recovery brings the previous
  release straight back. The database is untouched, because nothing else ran.
- If the undo exec itself fails, the new release retries it 3 times. After that it
  keeps serving, and the marker stays, so the previous release's next start still
  restores the copy. It never exits on its own.

`state.json` records the last switch as `applied` (`applied`, `undone` or
`not-applied`, with a reason) and the paused version as `paused`.

**For services to follow updates across cold starts,** start the server from
`<data>/updates/current/infraternal-<arch>-musl` (S6 points the production unit
there). A unit that starts a fixed path runs the updated release only until its
next cold start.

The undo is recorded with its reason: `the new release failed its health check`,
`… did not pass its health check in time`, `… could not start serving`, `… stopped
during its health check` (crash, kill or reboot, the cold case) or `… could not
start` (the exec was refused).

**Staging proof.** `staging-trust` builds (never production;
`check-production-trust.py` refuses them) read three more variables:
`INFRATERNAL_STAGING_BUILDS_ORIGIN` (a `http://127.0.0.1:` channel),
`INFRATERNAL_STAGING_UPDATE_SECONDS` (first check, check period and quiet window)
and `INFRATERNAL_STAGING_UNHEALTHY_VERSION` (that version fails its health
check). The root proof
`deploy_staging::update_staging::auto_update_applies_warm_and_undoes_a_bad_release`
uses them to test a bad release, updates off, a withdrawn release and a good
release on a real unit.

# Add-host payloads

For the server's own architecture, bootstrap copies the running executable.
For another architecture, it requests that exact server version from the
public builds host and verifies before SSH uploads anything [225]. Channel
settings never change this selection: an edge server installs its exact edge
version on the new host, even while its future release channel remains stable. The existing
configured server state directory determines the rootful/rootless location;
verified files live under `releases/<version>/<architecture>/`. Each cache hit
reverifies the signed manifest, exact version and payload. A cold miss makes
four bounded requests (manifest, signature, VERSION, payload); warm reuse
makes none. Downloads use private `download-<canonical UUID>/` staging
in the same version directory. Only after signature, version and payload
verification does one atomic directory rename publish the complete bundle.
At resolver startup and before a newly verified bundle is published, cleanup
reclaims abandoned staging for that version. It only unlinks recognized,
owned, private regular files with a single link inside owned private staging.
Other names, symlinks, shared files and unknown contents remain untouched.
A lifetime directory flock protects each active download; creation and cleanup
also share a short version-directory flock to avoid collecting a just-created
directory before its lifetime lock is acquired. No background task runs for this
resolver. A failed fetch or check stops at “Get the arm64 binary” (or x86_64)
with a plain reason. Payload resolution has a 60-second maximum, shortened to
finish before the enclosing installation deadline, so a stalled builds host
also retains its named architecture step.

A development binary is built without `INFRATERNAL_RELEASE_BUILD=1`. Only a
404 for its version's manifest permits the adjacent local static payload
fallback. Network, TLS, missing payload and signature failures never enable it.
Existing explicit bootstrap payload paths apply to this development fallback.

The update handoff (#154) calls
`infraternal_server::release_verify::verify_release_file(&File, name, sums, sig)`.
It verifies the exact opened descriptor and preserves its file offset. The
caller must prevent file writes until it uses the verified descriptor.

# Local verification

```sh
python3 scripts/release/test.py
TRACER_TEST_PORT=4357 bun test scripts/release/review.test.ts scripts/release/worker.test.ts
cargo build -p infraternal
INFRATERNAL_BIN="$CARGO_TARGET_DIR/debug/infraternal" python3 scripts/release/channel_cli_test.py
cargo test -p infraternal-server release_verify
cargo test -p infraternal-server release_payload
cargo test -p infraternal-server release_latest
cargo test -p infraternal-plugin-release
cargo test -p infraternal-plugin-api release_version
systemd-run --user --scope -p CPUWeight=10000 \
  cargo test --release -p infraternal-server bench_bounded_metadata_verification -- --ignored --nocapture
systemd-run --user --scope -p CPUWeight=10000 \
  cargo test --release -p infraternal-server bench_latest_fifty_callers -- --ignored --nocapture
systemd-run --user --scope -p CPUWeight=10000 \
  cargo test --release -p infraternal-plugin-release channel_reads_at_fifty_concurrent_callers -- --ignored --nocapture
systemd-run --user --scope -p CPUWeight=10000 \
  cargo test --release -p infraternal-server verification_twenty_megabytes_fifty_runs -- --ignored --nocapture
systemd-run --user --scope -p CPUWeight=10000 \
  cargo test --release -p infraternal-server cross_architecture_cold_and_warm_cache_measurements -- --ignored --nocapture
ASAN_OPTIONS=detect_odr_violation=0 \
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=none \
  systemd-run --user --scope -p CPUWeight=30 cargo +nightly-2026-10-01 fuzz run release_channel -- -max_total_time=300 -max_len=70000 -rss_limit_mb=2048
python3 fuzz/seed_release.py
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=none \
  systemd-run --user --scope -p CPUWeight=10000 cargo +nightly-2026-10-01 fuzz build release_verify
ASAN_OPTIONS=detect_odr_violation=0 \
  CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=none \
  systemd-run --user --scope -p CPUWeight=30 cargo +nightly-2026-10-01 fuzz run release_verify -- -max_total_time=300 -max_len=70000 -rss_limit_mb=2048
```

Set the job's scratch `CARGO_TARGET_DIR` for every command. The explicit
ASan option matches the fuzz runner's generated command; memory instrumentation
remains enabled. The script tests
copy the scripts and trust file into an isolated fixture, generate a throwaway
key, and use a loopback bucket/signer. Production key injection is unavailable.
`RELEASE_TEST_ORIGIN` exists solely for an explicit loopback HTTP stand-in;
the default endpoints always use HTTPS. These tests never contact the live
bucket or Worker.

# Review checklist

- Trust anchors are public, included verbatim at compile time; OpenSSL and Hyper
  were already approved dependencies. No new cryptographic engine is introduced.
- SSHSIG fields consume every byte, with exact algorithms/namespace and bounded
  lengths. OpenSSH fixtures cover every armor/envelope/manifest/payload byte.
- The signed VERSION and payload use opened descriptors. Cache reuse always
  reverifies; private owned directories, regular files, single links and no-follow
  opens reject unsafe cache state. The caller must prevent local writes until use.
- Downloads enforce HTTPS peer/hostname verification, request/body deadlines,
  byte ceilings and no redirects. HTTP/trust overrides exist only in test builds.
- SSH is the existing removable plugin, and its existing installation transaction
  does all host writes. A failed payload source never uploads; no background
  release work runs while the component is off.
- Environment tokens reach curl through stdin, with tracing disabled. No signing
  key, credential file, secret argument or provider diagnostic is recorded.
- Publisher decoding of R2 preflight and Worker responses rejects duplicate
  fields at every depth. The
  fixed per-user flock refuses concurrent same-version publishers even with
  different build directories; cross-machine
  serialization is required because REST conditional PUT is not guaranteed.
- Stable defaults never depend on the running binary's channel. Edge requires
  explicit confirmation in both adapters; returning to stable is one action.
- Channel pointers are bounded strict objects; signed VERSION binds the exact
  pointer version and selected channel. Missing stable never requests edge.
- Release actions belong to a removable runtime-switchable plugin; construction
  starts no network or polling work, and disable cancels in-flight socket work.
  The update timer (#211 S3) starts only in root release builds, sleeps between
  checks and skips checks while the plugin is disabled.
- The channel CLI/API slice adds no UI; UI approval and screenshot review stay
  with the owner’s separate UI work.
