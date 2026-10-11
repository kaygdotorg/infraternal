<!-- Operator contract for immutable signed releases and architecture-specific bootstrap payloads [184,213,220,224,225]. -->
# Signed releases

The workspace version in `Cargo.toml` identifies a release. The public bucket
contains `releases/<version>/infraternal-{x86_64,aarch64}-musl`, the server
`infraternal` copy, `VERSION`, `SHA256SUMS`, `SHA256SUMS.sig`, and `releases/index.json`.
The release-signer Worker hashes R2 objects itself, signs the manifest and adds
the index entry. The pipeline never holds the signing private key [224]. The signed `VERSION`
file contains the workspace version followed by a newline. Both the downloader
and public verification compare it with the requested version: the signature
on SHA256SUMS alone does not authenticate the URL and cannot prevent replay
of a valid older release under another version path.

Build on Linux with the pinned Rust toolchain and both musl targets installed:

```sh
export CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/release-pipeline/target"
scripts/release/build
```

This reuses `scripts/package-release`, `.cargo/musl-{cc,ar}.sh` and
`scripts/auth-toolchain` (checksum-pinned Zig 0.15.2 [213]). It produces the
complete immutable bundle in `$CARGO_TARGET_DIR/releases/<workspace-version>`.
The build marks the binaries as release builds: missing public releases and
verification failures cannot enable the development fallback.

The orchestrator supplies `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` and
`RELEASE_CALLER_TOKEN` in the publishing process environment, then runs:

```sh
scripts/release/publish <workspace-version>
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

# Add-host payloads

For the server's own architecture, bootstrap copies the running executable.
For another architecture, it requests that exact server version from the
public builds host and verifies before SSH uploads anything [225]. The existing
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
TRACER_TEST_PORT=4299 bun test scripts/release/review.test.ts
cargo test -p infraternal-server release_verify
cargo test -p infraternal-server release_payload
systemd-run --user --scope -p CPUWeight=10000 \
  cargo test --release -p infraternal-server verification_twenty_megabytes_fifty_runs -- --ignored --nocapture
systemd-run --user --scope -p CPUWeight=10000 \
  cargo test --release -p infraternal-server cross_architecture_cold_and_warm_cache_measurements -- --ignored --nocapture
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
- R2 preflight and Worker JSON reject duplicate fields at every depth. The
  fixed per-user flock refuses concurrent same-version publishers even with
  different build directories; cross-machine
  serialization is required because REST conditional PUT is not guaranteed.
- Independent visual judgment remains a reviewer responsibility. Production-build
  screenshots accompany the browser test evidence; no new UI primitive is added.
