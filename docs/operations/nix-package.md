<!-- Reproducible static release packaging and the service boundary for #274 [7,17,20,213,243]. -->
# Nix package

Build a clean, committed checkout with `nix build .#packages.x86_64-linux.default`.
The same expression is exposed as `packages.aarch64-linux.default`; it builds
natively on that architecture. The lock file pins both nixpkgs and Rust's
overlay; `rust-toolchain.toml` pins Rust, its components and both musl targets.
Build VMs run this through `~/infraternal-ops/build-slot`, with `--max-jobs 1
--cores 4` on compute01. No build or installation happens on a production host.
The builders also lower their own priority to nice 10: daemon-spawned build
processes do not inherit the client's build-slot priority. A host policy that
already assigns a lower priority is preserved.

The output contains:

- `bin/infraternal`, a convenience symlink to the static server executable.
- `bin/infra` and `share/infraternal/infra`, relative aliases to the canonical
  executable in each directory [349].
- `share/infraternal/infraternal`, the server for the selected architecture.
- `share/infraternal/infraternal-{x86_64,aarch64}-musl`, full host payloads.
- `share/infraternal/infraternal-{x86_64,aarch64}-session-musl`, session payloads.
- `share/infraternal/web`, the production tracer build, including fonts, WASM,
  CSS, workers and precompressed assets.
- `share/infraternal/{SOURCE,VERSION,SHA256SUMS}`, the source revision, workspace
  version and checksums for all regular bundle files.

All host payloads remain beside the server: runtime payload discovery uses the
executable's directory. Nix does not wrap, strip, patch or otherwise fix up the
shipping binaries. The static bundle has its own derivation, so changing only
the revision/timestamp used for final assembly can reuse compiled binaries.
Build-time script shebangs resolve to Nix interpreters inside
the sandbox. Cargo uses the same profiles, musl targets, Rust LLD and
`scripts/static-cargo` recipe as `scripts/package-release`. It vendors the
complete Cargo.lock closure through `rustPlatform.importCargoLock`, then builds
offline. The build pins `SOURCE_DATE_EPOCH=315532800`, matching the normal
Nix dev shell's epoch and OpenSSL's embedded build date. Zig uses the exact archive and checksum from `scripts/auth-toolchain`
(D213), with no additional Zig from nixpkgs. The compiler executable stays
unchanged. Two build-library adaptations let its native generators work in
the sandbox: host ABI discovery reads Nix's `env` ELF, and the build runner
passes that resolved host target explicitly to generator compilations.
Explicit musl target queries keep their shipping arguments. The native source archive and its
Zig package cache are fixed-output inputs. Bun installs the frozen lock file
without lifecycle scripts or unused optional native peer tooling into a
fixed-output dependency derivation; the web
build has no network access.

The tracer's normal build embeds its build wall clock and reads HEAD from git.
Nix supplies `INFRATERNAL_BUILD_DATE` from the flake source's last-modified time
and `INFRATERNAL_BUILD_COMMIT` from its revision. A regular build can set the
same values to compare bytes. Dirty checkouts have no valid clean revision and
are unsuitable for production provenance. All other normal tracer defaults
remain unchanged.

For a byte comparison, build the normal `scripts/package-release` bundle at
the same clean commit with the same pinned dev shell. Compare `sha256sum` and
`stat -c %s` for each of its five executables against
`result/share/infraternal/`. Then build the normal web app with
`INFRATERNAL_BUILD_COMMIT=$(git rev-parse HEAD)` and
`INFRATERNAL_BUILD_DATE=$(date -u -d @$(git show -s --format=%ct HEAD) +%Y-%m-%dT%H:%M:%S.000Z)`.
Compare the complete relative file lists and every file's hash, including
precompressed files. Keep preview and readable-build flags unset in both
builds. Equal executable sizes alone do not establish reproducibility.

This source-built package is an unsigned build, with the workspace version and
normal `scripts/static-cargo` identity. It does not manufacture `GATE`,
`MANIFEST`, `MANIFEST.sig`, or a signed stable/edge identity. Those records belong
to the release admission/signing pipeline. A Nix build alone does not authorize
a production replacement; #274 must preserve that pipeline's admission checks.
A release builder can use `default.override { releaseVersion = "x.y.z"; }`
(with an actual valid version) to set the existing explicit release-build/version
inputs for all five executables. This changes their embedded identity and VERSION;
compare against normal scripts with those same environment inputs. It still
requires external release gating and signing.

## Example systemd unit

This is a documentation template, not a module or an installation step.
Substitute the accepted immutable output path for `@PACKAGE@` and choose the
listener/proxy parameters during #274 staging. Use the real executable path,
not a profile or `bin/infraternal` symlink. This does not make Nix store paths
eligible for the application's signed warm replacement: the bundle is unsigned,
and compute01's `/nix/store` is root:nixbld mode 1775, which the existing
protected-parent validation rejects. This template supports a cold systemd
stop/start; retain the accepted previous output for a cold rollback. Do not
relax restart validation or change store permissions as a packaging workaround.
The migration's SELinux, firewall, proxy-source, CA unlock, backup and rollback
checks still apply.

```ini
[Unit]
Description=infraternal server
Wants=network-online.target
After=network-online.target netbird.service

[Service]
Type=simple
User=root
UMask=0077
StateDirectory=infraternal
StateDirectoryMode=0700
RuntimeDirectory=infraternal
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
WorkingDirectory=/var/lib/infraternal
ExecStart=@PACKAGE@/share/infraternal/infraternal server --data /var/lib/infraternal --listen 127.0.0.1:7011 --public-origin https://infraternal.kayg.org --web-root @PACKAGE@/share/infraternal/web
Restart=on-failure
RestartSec=2
KillMode=process
Delegate=yes
LimitMEMLOCK=8388608

[Install]
WantedBy=multi-user.target
```

This minimal loopback example needs the approved ingress and remote-host
listener parameters before it can serve #274. State and runtime data remain
outside the immutable output. The runtime directory is retained across service
stops because `KillMode=process` allows session shims to survive; reboot still
clears `/run`. Host login, PAM, systemd and networking programs
remain host integrations; their Nix provisioning is separate from this package.
Do not add a broad inherited PATH to bypass the host daemon's sanitized login
environment. Keep previous store outputs rooted for the rollback hold.
