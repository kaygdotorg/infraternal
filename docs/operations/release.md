<!-- Operator contract for immutable signed releases and architecture-specific bootstrap payloads [184,213,220,224,225,226]; S3 publication #211. -->
# Signed releases

Stable releases use the workspace `x.y.z` version in `Cargo.toml`. Edge releases
use `edge-YYYYMMDDTHHMMSSZ`, stamped from UTC at build time [226]. The public bucket
contains `releases/<version>/infraternal-{x86_64,aarch64}-musl` (the add-host
payloads, without a `server` command), the initial-shell
`infraternal-{x86_64,aarch64}-session-musl` images, the x86_64 server image
`infraternal` (the only file a server's updater stages, J1134), the web app `infraternal-web.tar` (#211 S6), `VERSION`, `SHA256SUMS`, `SHA256SUMS.sig`, `releases/index.json`, and `releases/channels/<channel>.json`.
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
complete immutable bundle in `$CARGO_TARGET_DIR/releases/<version>`. It also
builds the web app (`scripts/release/web-archive`, which needs `bun`) and packs it
as `infraternal-web.tar`: the browser app the release's images serve (see
"Starting the boot pointer" below). New
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

### Signed and notarized macOS bundle (D321, #615)

App windows on macOS require Developer ID-signed, notarized executables sharing
one Apple Team ID (`infraternal`, `infraternal-desktop-helper`, and
`InfraternalCaptureHelper.app`), because the agent's cross-user helper check
(`crates/infraternal-shim/src/code_identity.rs`) rejects ad-hoc or unsigned
helpers and macOS TCC/Gatekeeper require a signed, stapled app bundle.

This optional release step runs on the arm64 Mac build host inside the
repository's Nix dev shell (`nix develop`), using:

- a **temporary, dedicated signing keychain** created for the single build and
  deleted on exit (the login keychain and every other keychain on the Mac are
  never opened, unlocked or modified);
- an App Store Connect API key directory on the Mac (`~/.config/asc` holding
  `AuthKey_<KEY_ID>.p8` mode `0600`, `key-id.txt`, and `issuer-id.txt`);
- the Developer ID Application `.p12` and its password read from 1Password on
  the control host and streamed over SSH stdin into `scripts/release/macos-signed`.

No signing certificate, password, or API key is stored in the repository, passed
in argv, or written to logs:

```sh
# On the control host (reads the 1Password service-account token in a subshell
# and streams the .p12 + password over SSH stdin to the arm64 Mac build host):
(
  OP_SERVICE_ACCOUNT_TOKEN="$(cat ~/.config/1passwd/infraternal.env)"
  export OP_SERVICE_ACCOUNT_TOKEN
  tmp="$(mktemp -d)" && chmod 0700 "$tmp" && trap 'rm -rf -- "$tmp"' EXIT
  op read 'op://Apps / Infraternal/Apple Certificates/Developer ID Application.p12' --out-file "$tmp/cert.p12" >/dev/null
  op read 'op://Apps / Infraternal/Apple Certificates/password' > "$tmp/pass.txt"
  python3 -c '
import base64, json, sys
print(json.dumps({
    "p12_b64": base64.b64encode(open(sys.argv[1], "rb").read()).decode("ascii"),
    "p12_pass": open(sys.argv[2], encoding="utf-8").read().rstrip("\r\n"),
}))
' "$tmp/cert.p12" "$tmp/pass.txt"
) | netbird ssh kayg@std.vpn.kayg.org \
  'nix develop /path/to/checkout -c /path/to/checkout/scripts/release/macos-signed /absolute/output/dir --asc-dir "$HOME/.config/asc"'
```

`scripts/release/macos-signed` invokes `scripts/macos-release` with
`--delete-keychain` and `--asc-dir`, builds the `release_macos_host_cargo_args`
CLI and `release_macos_helper_cargo_args` desktop helper, assembles
`InfraternalCaptureHelper.app` with `scripts/desktop-helper-bundle`, signs all
three with the hardened runtime and a secure timestamp, submits to Apple's
notary service, staples `InfraternalCaptureHelper.app`, verifies `codesign
--verify --strict`, verifies all three share one Team ID and satisfy the agent's
helper `PeerRequirement`, runs `spctl -a -vv` and `xcrun stapler validate` on
the app bundle, writes `infraternal-macos-arm64-<version>-<commit>.zip` and
`SHA256SUMS`, and deletes the temporary keychain before exiting.

To install the signed bundle into an existing user-mode macOS install
(`~/Library/Application Support/infraternal/bin`, D395) and restart the agent:

```sh
unzip -q infraternal-macos-arm64-<version>-<commit>.zip -d /tmp/infraternal-mac-unpack
src="/tmp/infraternal-mac-unpack/infraternal-macos-arm64-<version>-<commit>"
bin="$HOME/Library/Application Support/infraternal/bin"
mkdir -p "$bin"
# Stage and atomically replace binaries so macOS does not invalidate running code pages.
install -m 0755 "$src/infraternal" "$bin/infraternal.new" && mv -f "$bin/infraternal.new" "$bin/infraternal"
ln -sfn infraternal "$bin/infra"
install -m 0755 "$src/infraternal-desktop-helper" "$bin/infraternal-desktop-helper.new" && mv -f "$bin/infraternal-desktop-helper.new" "$bin/infraternal-desktop-helper"
rm -rf "$bin/InfraternalCaptureHelper.app.new"
ditto "$src/InfraternalCaptureHelper.app" "$bin/InfraternalCaptureHelper.app.new"
rm -rf "$bin/InfraternalCaptureHelper.app"
mv "$bin/InfraternalCaptureHelper.app.new" "$bin/InfraternalCaptureHelper.app"
launchctl kickstart -k "gui/$(id -u)/kayg.infraternal.agent"
```

The orchestrator supplies `CLOUDFLARE_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`,
`R2_SECRET_ACCESS_KEY` and `RELEASE_CALLER_TOKEN` in the publishing process
environment, then runs:

```sh
scripts/release/publish <version>
```

The R2 pair is an S3 API key scoped to the one bucket `infraternal-builds`
(object read and write). That is the narrowest grant: no account-wide R2 and no
Workers access. `publish` talks to
`https://$CLOUDFLARE_ACCOUNT_ID.r2.cloudflarestorage.com/infraternal-builds/...`
and lets curl sign each request with SigV4 (`--aws-sigv4 aws:amz:auto:s3`).
`CLOUDFLARE_API_TOKEN` is no longer used: the Cloudflare REST objects API is not
called (#211). `RELEASE_CALLER_TOKEN` is for the signer Worker only.

Do not put keys or tokens in shell arguments, checked-in environment files or
logs. Both the R2 pair and the caller token are passed to curl through its
configuration on stdin; the scripts never print them or write them to files, so
`/proc/<pid>/cmdline` of the curl child holds neither. The key id and secret must
use plain key characters, or the script refuses them before curl starts. Only the
owner may change/deploy the signer [224]. Every authenticated and public request
includes a User-Agent.

Publication refuses an existing object or signed release. It uploads the whole
bundle, asks the Worker to sign, downloads the manifest, signature and payloads,
and verifies the signature and all hashes before reporting success. Interrupted
publication leaves an immutable partial release; investigate it rather than
repeating uploads over existing objects.

Admission and uploads work like this:

- **Listing.** A ListObjectsV2 request with `prefix=releases/<version>/` covers
  every object, partial or unrelated. The page must be empty. A page that is
  empty but truncated is followed through its continuation token for at most 5
  pages; after that publication stops.
- **Strict XML.** The reply is read up to 1 MiB, with no DTD or entity allowed
  (`response.py`). It must be a `ListBucketResult` for this bucket and prefix,
  with `KeyCount` 0, a consistent `IsTruncated` and token, and no repeated or
  unknown top-level element. Any `Contents` entry is refused even when the count
  says 0. Anything else stops with a plain reason, and no provider diagnostics
  are echoed.
- **Upload.** Each PUT is signed, sends `If-None-Match: *` and checks the HTTP
  status through curl (`--fail`); its reply body is bounded and discarded. R2
  supports conditional PutObject on its S3 API, evaluated atomically against the
  committed state, so a concurrent writer gets 412 instead of replacing an
  object ([R2 conditional operations](https://developers.cloudflare.com/r2/api/s3/conditional-operations/),
  [S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/)).
  The old REST upload had no such promise. Even so, serialize publishers across
  machines: the listing is not a distributed lock.
- **Lock.** A nonblocking `flock` is held for the entire publication, including
  signing and public verification. The fixed per-user lock path is
  `${XDG_STATE_HOME:-$HOME/.local/state}/infraternal/release-publish/<version>.lock`,
  independent of `CARGO_TARGET_DIR` and the worktree. The state path must be
  absolute; the lock directory and file must be owned and private. Lock files
  remain in place: unlinking a held lock would allow a second writer to lock a
  new inode. The kernel releases the lock when its last descriptor closes;
  in-flight child requests retain it after an abrupt publisher stop.
- **Worker reply.** The signer's JSON reply is bounded and rejects duplicate
  fields recursively, including nested objects.

This pipeline does not consume `releases/index.json`.

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
infraternal skill server channel
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
the server downloads the server image `infraternal`, and `infraternal-web.tar` when the
signed list names it, verifies them with the same
verifier as `restart --binary` (signed `SHA256SUMS`, `SHA256SUMS.sig` and
`VERSION`) and keeps them in `<data>/updates/staged/`. The same version does
nothing. A release whose signed list names no `infraternal` is refused before any
image download ("the release does not publish a server image for this machine"):
the `infraternal-<arch>-musl` files beside it are the add-host payloads, which have no
`server` command and are never staged (J1134). Releases publish one server image,
built for x86_64 (`scripts/release/build` pins it), so the check runs only on x86_64
Linux; an aarch64 server reports updates off until the pipeline publishes an aarch64
server image under its own name. An older version or another channel's release is refused; only an
explicit request (a D295 rollback or a channel switch, coming in S4/S5) may
stage one, and never without the signature. Staging needs 256 MiB free
(the 128 MiB image bound, the 64 MiB web build bound and a 64 MiB reserve) and keeps only one release.
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
   sealed copy and never reopens it by path), with its web build unpacked into
   `web/` beside the image;
3. copies its own image to `updates/previous/`, with its own release's `web/`
   (hard links), and writes one database copy beside it (`VACUUM INTO`, D295);
4. writes `updates/pending.json`, naming both releases by the SHA-256 of their
   images.

**The trial.** The new release has 2 minutes to pass its health check. `/healthz`
must answer 200 on its own listener, a write transaction must commit, and the CA
must be unlocked if it was before. On a pass, `updates/current` (a symlink, the
boot pointer) moves to `releases/<new>`. Other installed releases are removed,
and `previous/` is kept until the next update, so S5's manual roll back can use
it. Once committed, the root server also updates the world-executable CLI copy at
`/usr/local/lib/infraternal/infraternal` (see "CLI command on `PATH`" below).

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
`<data>/updates/current/infraternal` (S6, below). A unit that starts a
fixed path runs the updated release only until its next cold start.

The undo is recorded with its reason: `the new release failed its health check`,
`… did not pass its health check in time`, `… could not start serving`, `… stopped
during its health check` (crash, kill or reboot, the cold case) or `… could not
start` (the exec was refused).

**Staging proof.** `staging-trust` builds (never production;
`check-production-trust.py` refuses them) read three more variables:
`INFRATERNAL_STAGING_BUILDS_ORIGIN` (a `http://127.0.0.1:` channel),
`INFRATERNAL_STAGING_UPDATE_SECONDS` (first check, check period and quiet window)
and `INFRATERNAL_STAGING_FAULTS`, space-separated `<version>=<fault>` entries
where the fault is `unhealthy` (the health check fails), `timeout` (it never
answers, so the 2-minute limit ends the trial), `migration` (startup fails like a
broken migration) or `exec` (the exec of that release is refused).
`scripts/update-proof-vm` runs the root proof in a throwaway NixOS microVM, with
real terminal sessions, and covers each of those faults plus a kill and a hard
reboot during the trial, updates off, a withdrawn release and a good release.

## Updating from the server machine (#211, D400)

On the machine that runs the server, root (or the account the server runs as)
controls updates from a shell:

```sh
sudo infraternal server update status
sudo infraternal server update check                 # check the channel now
sudo infraternal server update check <version>       # stage exactly this release (held)
sudo infraternal server update apply [<version>]     # switch now, wait for the health check
sudo infraternal server update rollback              # back to the previous version (D295)
sudo infraternal server update cancel                # drop a held release
sudo infraternal server update history
sudo infraternal server update settings --quiet-minutes 10
sudo infraternal server update settings --automatic off   # stage only; apply when asked
infraternal skill server update apply                # the contract an AI agent reads
```

Every command takes `--data <folder>` (default: the installed server's data
folder) and `--json` for the stable result envelope; the whole answer of the
action is in `data.update`.

These are the same `release.update.*` actions as the web app's Updates page,
run inside the running server over its private control socket
(`<data>/restart/control.sock`, 0600 in a 0700 folder). The server checks the
caller's kernel credentials (`SO_PEERCRED`): only root and the server's own
account are served, and they need **no passkey**, because they can already
replace the binary (D400). From any other device the owner still needs a recent
passkey tap. The client checks the other end too: the process behind the socket
must run as this account, or, for root, as the account that owns the data folder.

`apply` and `rollback` wait (up to 5 minutes) until the switch is over: the new
release passed its 2-minute health check and became the boot pointer, or the
server went back by itself. The exit code is 0 only when the update applied (or
the roll back finished); an undone update exits 1 with the reason. The warm
restart closes the connection that asked, so the outcome is read from the status
the server records, not from the reply. `--no-wait` returns once the switch has
started. A server older than this command does not answer the request (the
command says so); move it once with `infraternal server restart --binary`.

The production flow (owner, 2026-11-22): publish a signed edge release after
each green dev gate, then on the server `sudo infraternal server update check`
and `sudo infraternal server update apply`.

**Automatic apply (owner setting, J1130).** By default a staged release is applied by itself
in the quiet window. `settings --automatic off` (or `{"automatic": false}` in
`release.update.settings`) turns that off: the server still checks and stages on schedule, so
`status` shows what is available, but it never switches alone; only an explicit
`release.update.apply` (the `apply` command or the Updates page) does. `--automatic on`
restores the default. The choice is `automatic` in `state.json` and in the status, and it
survives the D295 database restore of an undone update. Production is set to off, so it moves
only when the owner or the orchestrator says so.

## Starting the boot pointer, and moving an existing install onto it (#211 S6)

**What starts.** A server that follows its updates is started from
`<data>/updates/current/infraternal`, the release's server image (never the
`infraternal-<arch>-musl` add-host payloads). `current` is the boot pointer: it
names `releases/<version>/`, and only a release that passed its health check moves it
(D295). So a cold start (a crash, `systemctl restart`, a reboot) starts the newest
healthy release, and after an undone update it starts the previous one.

**Which web build is served.** A release carries its web app as `infraternal-web.tar`,
which is unpacked into `releases/<version>/web/`. A server whose image runs from
`<data>/updates/releases/<version>/` (directly or through `current`; resolved once at
start) and whose folder has `web/` serves that folder, and ignores an inherited
`--web-root` (the start log says `release_web_root` and names the ignored flag). The
flag is inherited because a warm switch keeps the process's arguments, so after an
update it would name the build that ran before, whose script chunks the new server
does not have. `updates/previous/` keeps the running release's `web/` too, so a manual
roll back serves its own. Anything else (a fixed install path, a release without a web
build) serves `--web-root` as before.

**CLI command on `PATH` (#211).** `<data>/updates/current/infraternal` lives inside
the `0700` root-only data folder, so non-root users cannot exec through it. To keep
`infraternal` on `PATH` aligned with the running server across automatic quiet-window
updates, Web UI updates, `server update apply`, `server update adopt`, and manual
rollbacks, the root server (and `adopt`) maintains a world-executable copy outside
`<data>`:

- `/usr/local/lib/infraternal/infraternal` (`0755`, root-owned, atomically replaced
  via `rename`, and labeled `bin_t` on `SELinux` hosts before rename);
- `/usr/local/lib/infraternal/infraternal.previous` (`0755`, kept until the next
  switch so a manual rollback restores the previous CLI copy atomically);
- `/usr/local/bin/infraternal` -> `/usr/local/lib/infraternal/infraternal`.

`/usr/local/bin/infraternal` is created or re-pointed only when it is missing or
already a symlink to an infraternal release (for example an earlier `/opt/infraternal/...`
or `/var/lib/infraternal/...` link). A foreign regular file, directory, or symlink to
another program is refused loudly and never overwritten (`adopt` refuses in preflight;
the running server logs an error without rolling back a healthy committed release).

**`server init --system`** writes `ExecStart=<data>/updates/current/infraternal server …`
once the data folder has a boot pointer, keeping every other flag, and leaves out
`--web-root` when that release has its own web build. A fresh install has no pointer
yet and starts the installed binary, as before. On SELinux hosts (where
`/sys/fs/selinux/enforce` exists or `getenforce` is not `Disabled`), `server init
--system` also adds the persistent file-context rule `semanage fcontext -a -t bin_t
"<data>/updates(/.*)?"` (skipped if that exact rule already exists) and runs
`restorecon -R <data>/updates`, so systemd can execute the boot pointer and later
staged releases instead of failing with `203/EXEC` on `var_lib_t`. If `semanage` is
missing on an SELinux host, `server init --system` refuses and asks for
`policycoreutils-python-utils` instead of writing a unit that cannot start; `--dry-run`
prints the commands it would run. Non-SELinux hosts run no extra commands.

**`infraternal server update adopt <release folder>`** moves an existing server, once,
from a fixed path onto the boot pointer. It runs as root on the server machine. It
first checks everything and refuses with the reason if anything does not match: the
unit systemd loaded (`FragmentPath`) is a plain file with one `ExecStart` that runs an
infraternal server for this `--data`, no drop-in overrides `ExecStart`, the server runs
as root and is active, the running server says its version on its control socket,
the release folder is signed (verified like `restart --binary`), for this machine, and
not older than the running version, and on SELinux hosts `semanage`
(`policycoreutils-python-utils`) and `restorecon` are installed. Then it:

1. copies the release into `<data>/updates/releases/<version>/`, verifies the copies
   (image and web build), unpacks `web/`, and points `current` at it;
2. on SELinux hosts, adds `semanage fcontext -a -t bin_t "<data>/updates(/.*)?"` (if
   not already present) and runs `restorecon -R <data>/updates`, so the boot pointer
   and future staged releases carry `bin_t` and survive cold starts;
3. backs the unit up to `<data>/unit-backups/<unit>.<UTC stamp>` and rewrites only
   its `ExecStart` line: the program becomes the boot pointer, every flag stays, and
   `--web-root` goes when the release has its own web build; then `systemctl
   daemon-reload`;
4. restarts the running server warm into `releases/<version>/infraternal`, the same
   request as `infraternal server restart --binary`: same PID, the terminal sessions
   keep running, and the unlocked CA is handed over (D217);
5. waits up to a minute for the server to answer with the release's version. If it
   does not, the old unit is put back, and the command says how to start the
   previous build.

`--dry-run` does the checks and prints exactly what would change (the files, the old
and new `ExecStart`, the commands) and changes nothing. A second run on an adopted
server changes nothing. `--unit <name>` names another unit (default
`infraternal-server`), `--json` gives the envelope (`data.adopt`).

### Moving production (owner plan, 2026-11-22)

Production today: root, data `/var/lib/infraternal`, unit
`infraternal-server.service` written by the operator, `ExecStart=/opt/infraternal/<build>/infraternal server --data /var/lib/infraternal --web-root /opt/infraternal/<build>/web …`, CA unlocked.

1. **Run a build that has the update controls.** The running server must answer
   `sudo infraternal server update status` (J1127, dev `c621304ac` or later). Note the
   version it runs; the release you adopt must be the same or newer, on the same channel.
2. **Follow edge.** Existing servers default to stable, and only edge is published:
   `sudo infraternal server --data /var/lib/infraternal channel edge --yes`.
3. **Publish a signed edge release** from a green dev gate: `scripts/release/build
   --channel edge`, `scripts/release/publish <version>`, `scripts/release/verify
   <version>`.
4. **Fetch its server files onto the server** into a root-only folder. The server
   image is `infraternal`; `infraternal-x86_64-musl` in the same release is the
   add-host payload, which has no `server` command, so never use it here:
   ```sh
   v=<version>; b=https://builds.infraternal.com/releases/$v
   sudo install -d -m 700 /root/releases/$v && cd /root/releases/$v
   for f in SHA256SUMS SHA256SUMS.sig VERSION infraternal infraternal-web.tar; do
     sudo curl -fsSLo "$f" "$b/$f"
   done
   sudo chmod 700 infraternal
   sudo ./infraternal server --help >/dev/null && echo "server image ok"
   ```
5. **Dry run, with the release's own binary** (the installed `infraternal` predates
   the command). On SELinux hosts (such as EL-family servers), make sure
   `policycoreutils-python-utils` (`semanage`) is installed first; otherwise `adopt`
   refuses before changing anything:
   ```sh
   sudo /root/releases/$v/infraternal server update adopt /root/releases/$v --data /var/lib/infraternal --dry-run
   ```
   Read the `- ExecStart=` and `+ ExecStart=` lines: the program becomes
   `/var/lib/infraternal/updates/current/infraternal`, `--web-root` goes,
   everything else stays. On SELinux hosts, the dry run also lists the
   `semanage fcontext -a -t bin_t "/var/lib/infraternal/updates(/.*)?"` (if not
   already defined) and `restorecon -R /var/lib/infraternal/updates` commands that
   keep the boot pointer and future staged releases executable by systemd (`bin_t`,
   avoiding `203/EXEC` on `var_lib_t`). Never start a systemd unit directly from
   `/root` (`admin_home_t`) on an enforcing host.
6. **Move:** the same command without `--dry-run`. It answers "Moved the server from
   <old> onto <version> and the boot pointer, warm".
7. **Turn automatic apply off, right away** (production moves only when the owner or
   the orchestrator says so; J1130):
   ```sh
   sudo /root/releases/$v/infraternal server update settings --automatic off --data /var/lib/infraternal
   ```
   `server update status` then shows `automatic` off. The server still checks and
   stages, but never switches by itself.
8. **Check:** `sudo infraternal server update status` shows the version;
   `systemctl cat infraternal-server` shows the new `ExecStart`; the web app loads
   with the new build; the CA is still unlocked; terminals kept running.
9. **From now on** updates are `sudo infraternal server update check` and `sudo
   infraternal server update apply` after each publication (D400). `adopt`, committed
   switches, and manual rollbacks keep `/usr/local/lib/infraternal/infraternal` and
   `/usr/local/bin/infraternal` in sync automatically.
   `deploy.sh` must not be used any more: it replaces the `/opt` build and
   cold-restarts the unit, which now starts the boot pointer, so it would lock the CA
   and change nothing that runs.

**Undo the move:** put the backup back and restart into the old build warm:
```sh
sudo cp /var/lib/infraternal/unit-backups/infraternal-server.service.<stamp> /etc/systemd/system/infraternal-server.service
sudo systemctl daemon-reload
sudo infraternal server restart --binary /opt/infraternal/<build>/infraternal --rollback
```
`--rollback` hands the mesh identity back first (see `server restart`). `restart
--binary` admits only a signed image, so the `/opt` folder must still hold its signed
`SHA256SUMS`, `SHA256SUMS.sig` and `VERSION`; otherwise `sudo systemctl restart
infraternal-server` starts it cold (the CA then needs a passkey unlock). The boot
pointer stays in `updates/`, unused.

**Proof.** `PROOF=adopt scripts/update-proof-vm/build-inputs <inputs>` and
`scripts/update-proof-vm/run <inputs> <evidence>` run
`deploy_staging::update_staging::adopt::boot_pointer_adoption` as root in the throwaway
microVM: the production shape above (fixed `/opt` path, operator unit, live sessions,
CA unlocked), `adopt` warm, `server update apply` to a newer release, a cold
`systemctl restart` that starts the newer release from the boot pointer and serves its
web build, and a cold start after an undone update that starts the previous release.

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
the default endpoints always use HTTPS. The loopback origin also serves the S3
calls and recomputes each SigV4 signature, and the test inspects the live curl
child's `/proc/<pid>/cmdline` for secrets. These tests never contact the live
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
- The R2 key is bucket-scoped. The preflight XML is decoded strictly and
  bounded, and the Worker's JSON rejects duplicate fields at every depth. The
  fixed per-user flock refuses concurrent same-version publishers even with
  different build directories; `If-None-Match: *` makes R2 refuse an overwrite,
  and cross-machine serialization is still required for the listing.
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
