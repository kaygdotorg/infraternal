# The release bundle, built with the shipping scripts and their pinned toolchains.
{ lib, stdenv, rust-bin, rustPlatform, writeShellScriptBin, fetchurl, runCommand,
  bun, cacert, coreutils, curl, git, minisign, python3, perl, gnumake, xz, pkg-config, ripgrep,
  util-linux, binutils, source, revision, epoch, releaseVersion ? null }:
let
  # The daemon does not inherit the client's nice level. Lower only this
  # builder, without raising a priority already reduced by the host policy.
  lowerBuildPriority = ''
    if [ "$(nice)" -lt 10 ]; then renice -n 10 -p "$$" >/dev/null; fi
  '';
  rust = rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  arch = stdenv.hostPlatform.parsed.cpu.name;
  version = if releaseVersion == null
    then (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version
    else releaseVersion;
  # Same tarball and checksum table as scripts/auth-toolchain (D213, D328).
  zigArchive = (import ./zig.nix { inherit lib stdenv fetchurl runCommand xz; }).archive;
  zig = runCommand "infraternal-zig-0.17.0" { nativeBuildInputs = [ xz python3 util-linux ]; } ''
    ${lowerBuildPriority}
    mkdir -p "$out"
    tar -xJf ${zigArchive} --strip-components=1 -C "$out"
    # Keep the checksum-pinned compiler executable unchanged. Its build runner
    # must discover the Nix build host through an existing ELF, then pass that
    # resolved target explicitly to native generators. Cross targets keep the
    # shipping flags; only build-host discovery changes.
    substituteInPlace "$out/lib/std/zig/system.zig" \
      --replace-fail '"/usr/bin/env"' '"${coreutils}/bin/env"'
    python3 - "$out/lib/std/Build/Module.zig" <<'PY'
    from pathlib import Path
    import sys
    path = Path(sys.argv[1])
    before = "        if (!target.query.isNative()) {"
    after = """        if (target.query.isNative()) {
                const native_query = std.Target.Query.fromTarget(&target.result);
                try zig_args.appendSlice(&.{
                    "-target", try native_query.zigTriple(b.allocator),
                    "-mcpu", try native_query.serializeCpuAlloc(b.allocator),
                });
                if (target.result.dynamic_linker.get()) |dynamic_linker| {
                    try zig_args.append("--dynamic-linker");
                    try zig_args.append(dynamic_linker);
                }
            } else {"""
    source = path.read_text()
    assert source.count(before) == 1, "native build target boundary changed"
    path.write_text(source.replace(before, after))
    PY
  '';
  vtVersion = "1.0.0";
  vtFiles = builtins.listToAttrs (map
    (line: let fields = lib.splitString "  " line; in {
      name = builtins.elemAt fields 1;
      value = builtins.elemAt fields 0;
    })
    (lib.filter
      (line: line != "" && !(lib.hasPrefix "#" line))
      (lib.splitString "\n" (builtins.readFile ../scripts/libghostty-vt.sha256))));
  vtSourceName = "libghostty-vt-${vtVersion}.tar.gz";
  vtDepsName = "libghostty-vt-${vtVersion}-deps.tar.gz";
  vtSource = fetchurl {
    name = vtSourceName;
    url = "https://release.files.ghostty.org/libghostty-vt/${vtVersion}/${vtSourceName}";
    sha256 = vtFiles.${vtSourceName};
  };
  vtSourceSignature = fetchurl {
    name = "${vtSourceName}.minisig";
    url = "https://release.files.ghostty.org/libghostty-vt/${vtVersion}/${vtSourceName}.minisig";
    sha256 = vtFiles."${vtSourceName}.minisig";
  };
  vtDeps = fetchurl {
    name = vtDepsName;
    url = "https://release.files.ghostty.org/libghostty-vt/${vtVersion}/${vtDepsName}";
    sha256 = vtFiles.${vtDepsName};
  };
  vtDepsSignature = fetchurl {
    name = "${vtDepsName}.minisig";
    url = "https://release.files.ghostty.org/libghostty-vt/${vtVersion}/${vtDepsName}.minisig";
    sha256 = vtFiles."${vtDepsName}.minisig";
  };
  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../Cargo.lock;
    # Fixed source hash for the commit pinned in Cargo.lock; required in the sandbox.
    outputHashes."gotatun-0.10.2" = "sha256-mS0CUgX9V/8z8GNYqnXzBaoaLOMGI/ffekINaWA4rks=";
  };
  bunDeps = stdenv.mkDerivation {
    name = "infraternal-bun-deps";
    src = lib.fileset.toSource {
      root = ../apps/tracer;
      fileset = lib.fileset.unions [ ../apps/tracer/package.json ../apps/tracer/bun.lock ];
    };
    nativeBuildInputs = [ bun cacert util-linux ];
    preUnpack = lowerBuildPriority;
    dontConfigure = true;
    buildPhase = ''
      export BUN_INSTALL_CACHE_DIR="$TMPDIR/bun-cache"
      # Optional native packages are development compilers and unused font peers.
      # Bun builds production assets without them, keeping this cache architecture-neutral.
      bun install --frozen-lockfile --ignore-scripts --omit optional
    '';
    installPhase = ''
      mkdir -p "$out"
      cp -R node_modules "$out/node_modules"
    '';
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = "sha256-PSBZH4iSSZJJSTImCUk4ayupmor08VwHXfXHR/vh7i4=";
    dontFixup = true;
  };
  rustupShim = writeShellScriptBin "rustup" ''
    if [ "$1" = which ] && [ -n "$2" ]; then
      command -v "$2"
      exit
    fi
    echo 'rustup: nix provides the pinned toolchain' >&2
    exit 1
  '';
  # Commit identity and web stamping do not invalidate the expensive static build.
  binaries = stdenv.mkDerivation {
    pname = "infraternal-static";
    inherit version;
    src = source;
    nativeBuildInputs = [ rust rustupShim python3 perl gnumake curl git minisign xz pkg-config ripgrep util-linux binutils ];
    preUnpack = lowerBuildPriority;
    dontConfigure = true;
    # The sandbox has no /usr/bin/env. Only build-time script interpreters are
    # rewritten; the final static executables are never patched.
    postPatch = "patchShebangs .cargo scripts";
    # Shipping binaries are already stripped by Cargo. Nix fixups must preserve
    # bytes, including the static musl ELF interpreter/relocation invariants.
    dontFixup = true;
    allowedReferences = [ "out" ];
    buildPhase = ''
      runHook preBuild
      export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$PWD/target"
      # Match mkShell's reproducible epoch, which the normal shipping build
      # inherits in nix develop (including OpenSSL's embedded build date).
      export CARGO_BUILD_JOBS="$NIX_BUILD_CORES" CARGO_NET_OFFLINE=true SOURCE_DATE_EPOCH=315532800
      mkdir -p "$CARGO_HOME"
      # Put vendored crates under the registry root understood by static-cargo,
      # so source locations retain /cargo/<name>-<version> rather than store paths.
      mkdir -p "$CARGO_HOME/registry/src"
      cp -RL ${cargoDeps} "$CARGO_HOME/registry/src/vendor"
      chmod -R u+w "$CARGO_HOME/registry/src/vendor"
      # Preserve Git source replacements as well as crates.io's. Only the vendor
      # location changes: Cargo must resolve every source offline in the sandbox.
      sed "s|directory = \"cargo-vendor-dir\"|directory = \"$CARGO_HOME/registry/src/vendor\"|" \
        ${cargoDeps}/.cargo/config.toml > "$CARGO_HOME/config.toml"
      # Keep the release scripts' one-Zig invariant without invoking a downloader.
      for target in "$CARGO_TARGET_DIR" "$CARGO_TARGET_DIR/bootstrap" "$CARGO_TARGET_DIR/session"; do
        mkdir -p "$target/auth-tools" "$target/vt-tools"
        ln -s ${zig} "$target/auth-tools/zig"
        ln -s ${vtSource} "$target/vt-tools/${vtSourceName}"
        ln -s ${vtSourceSignature} "$target/vt-tools/${vtSourceName}.minisig"
        ln -s ${vtDeps} "$target/vt-tools/${vtDepsName}"
        ln -s ${vtDepsSignature} "$target/vt-tools/${vtDepsName}.minisig"
      done
      ${lib.optionalString (releaseVersion != null) ''
        export INFRATERNAL_RELEASE_BUILD=1
        export INFRATERNAL_RELEASE_VERSION=${lib.escapeShellArg releaseVersion}
      ''}
      scripts/package-release "$TMPDIR/bundle" ${arch}
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      cp -R "$TMPDIR/bundle" "$out"
      runHook postInstall
    '';
    meta = {
      description = "Static server and matching host payloads";
      license = lib.licenses.agpl3Only;
      platforms = [ "x86_64-linux" "aarch64-linux" ];
    };
  };
in stdenv.mkDerivation {
  pname = "infraternal";
  inherit version;
  src = source;
  nativeBuildInputs = [ bun util-linux ];
  preUnpack = lowerBuildPriority;
  dontConfigure = true;
  dontFixup = true;
  allowedReferences = [ "out" ];
  buildPhase = ''
    runHook preBuild
    cp -R ${binaries} "$TMPDIR/bundle"
    chmod u+w "$TMPDIR/bundle"
    rm "$TMPDIR/bundle/SHA256SUMS"
    export INFRATERNAL_BUILD_COMMIT=${lib.escapeShellArg revision}
    export INFRATERNAL_BUILD_DATE="$(date -u -d @${toString epoch} +%Y-%m-%dT%H:%M:%S.000Z)"
    export TRACER_DIST=dist
    cp -R ${bunDeps}/node_modules apps/tracer/node_modules
    chmod -R u+w apps/tracer/node_modules
    (cd apps/tracer && bun run build)
    cp -R apps/tracer/dist "$TMPDIR/bundle/web"
    printf '%s\n' '${revision}' > "$TMPDIR/bundle/SOURCE"
    printf '%s\n' "$version" > "$TMPDIR/bundle/VERSION"
    (cd "$TMPDIR/bundle" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin" "$out/share/infraternal"
    cp -R "$TMPDIR/bundle/." "$out/share/infraternal/"
    ln -s ../share/infraternal/infraternal "$out/bin/infraternal"
    # Both entry directories expose the same replaceable canonical executable [349].
    ln -s infraternal "$out/share/infraternal/infra"
    ln -s infraternal "$out/bin/infra"
    runHook postInstall
  '';
  passthru = { inherit binaries bunDeps vtDeps cargoDeps zig; };
  meta = {
    description = "Static server, matching host payloads and web application";
    license = lib.licenses.agpl3Only;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "infraternal";
  };
}
