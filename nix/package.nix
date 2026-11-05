# The release bundle, built with the shipping scripts and their pinned toolchains.
{ lib, stdenv, rust-bin, rustPlatform, writeShellScriptBin, fetchurl, runCommand,
  bun, cacert, coreutils, curl, git, python3, perl, gnumake, xz, pkg-config, ripgrep,
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
  zig = runCommand "infraternal-zig-0.15.2" { nativeBuildInputs = [ xz python3 util-linux ]; } ''
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
  vtRevision = "a887df42c56f6de86c0fe6da9c4eeca37931e083";
  vtArchive = fetchurl {
    name = "infraternal-vt-${vtRevision}.tar.gz";
    url = "https://codeload.github.com/ghostty-org/ghostty/tar.gz/${vtRevision}";
    sha256 = "fb4b2f9ffa0af125983041fdbe4ef94d3fa79fb9f2d22b9c213c0e3847a866b6";
  };
  # Only fetched package sources enter the output, never native build caches.
  vtDeps = stdenv.mkDerivation {
    name = "infraternal-vt-deps-${vtRevision}";
    src = vtArchive;
    nativeBuildInputs = [ cacert util-linux ];
    preUnpack = lowerBuildPriority;
    dontConfigure = true;
    buildPhase = ''
      export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-cache"
      # Fetch-only mode skips lazy dependencies requested while configuring
      # the shipping build graph. Exercise that graph, then discard all objects.
      ${zig}/zig build -j2 -Demit-lib-vt=true -Doptimize=ReleaseFast \
        -Dcpu=baseline -Dtarget=x86_64-linux-musl -Demit-xcframework=false -Dapp-runtime=none \
        --prefix "$TMPDIR/native"
      test -s "$TMPDIR/native/lib/libghostty-vt.a"
    '';
    installPhase = ''
      mkdir -p "$out"
      cp -R "$ZIG_GLOBAL_CACHE_DIR/p" "$out/p"
    '';
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = "sha256-BfU58ccEGY7L08XD3VPCr05VWHyDxQ+kb+LDQiCC2l0=";
    dontFixup = true;
  };
  cargoDeps = rustPlatform.importCargoLock { lockFile = ../Cargo.lock; };
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
      # Optional native packages belong to unused font-package peer tooling.
      # Omitting them keeps this browser-only dependency tree architecture-neutral.
      bun install --frozen-lockfile --ignore-scripts --omit optional
    '';
    installPhase = ''
      mkdir -p "$out"
      cp -R node_modules "$out/node_modules"
    '';
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = "sha256-o9hhp0aYmmnLsfo1u9ZaA81ldO8hnF1ZSbhrkyB5d4Y=";
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
    nativeBuildInputs = [ rust rustupShim python3 perl gnumake curl git xz pkg-config ripgrep util-linux binutils ];
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
      cat > "$CARGO_HOME/config.toml" <<EOF
      [source.crates-io]
      replace-with = "vendored-sources"
      [source.vendored-sources]
      directory = "$CARGO_HOME/registry/src/vendor"
      EOF
      # Keep the release scripts' one-Zig invariant without invoking a downloader.
      for target in "$CARGO_TARGET_DIR" "$CARGO_TARGET_DIR/bootstrap" "$CARGO_TARGET_DIR/session"; do
        mkdir -p "$target/auth-tools" "$target/vt-tools/zig-cache"
        ln -s ${zig} "$target/auth-tools/zig"
        ln -s ${vtArchive} "$target/vt-tools/${vtRevision}.tar.gz"
        cp -R ${vtDeps}/p "$target/vt-tools/zig-cache/p"
        chmod -R u+w "$target/vt-tools/zig-cache/p"
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
