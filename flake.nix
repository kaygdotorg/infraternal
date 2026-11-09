# Development shell: the whole toolchain `scripts/verify fast` needs, from nix.
#
# `nix develop` gives every build machine the same compiler (read from
# rust-toolchain.toml, so the toml stays the single source of truth), the same
# JS runtime and the same helper tools. Nothing is installed outside nix.
{
  description = "infraternal build and development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      # verify fast targets Linux; on aarch64-darwin, scripts/macos-build-check
      # is the build and portable-test check (#320).
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system:
        f (import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; }));
    in {
      packages = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system:
        let pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
        in { default = pkgs.callPackage ./nix/package.nix {
          source = self.outPath;
          revision = self.rev or self.dirtyRev or "";
          epoch = self.lastModified or 0;
        }; });
      devShells = forAll (pkgs:
        let
          # Channel, components and musl targets come from rust-toolchain.toml.
          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          # .cargo/rustc.sh asks `rustup which rustc` for the compiler. The
          # toolchain is already pinned by nix, so answer that one query and
          # refuse everything else; real rustup would download a compiler.
          rustupShim = pkgs.writeShellScriptBin "rustup" ''
            if [ "$1" = which ] && [ -n "$2" ]; then
              command -v "$2"
              exit
            fi
            echo "rustup shim: only 'rustup which <tool>' is supported (nix provides the toolchain)" >&2
            exit 1
          '';
          # The pinned Zig as a fixed-output derivation (D213, D328).
          # scripts/auth-toolchain copies it into the target directory instead
          # of downloading the same tarball again.
          zig = pkgs.callPackage ./nix/zig.nix { };
        in {
          default = pkgs.mkShell {
            INFRATERNAL_ZIG = zig.unpacked;
            packages = [
              rust rustupShim
              pkgs.cargo-deny          # cargo-deny gate (deny.toml)
              pkgs.bun                 # TypeScript tests, tracer build
              pkgs.nodejs_26           # JavaScript CLI shebangs in type checks
              pkgs.vim                 # Real-editor terminal repaint fixture
              pkgs.openssh             # Release-signature and SSH key fixtures
              pkgs.minisign            # Verify signed libghostty-vt source archives
              pkgs.python3             # release and fixture scripts
              pkgs.gnumake pkgs.perl   # vendored OpenSSL build drivers
              pkgs.gcc                 # host-side build scripts and proc macros
              pkgs.curl pkgs.xz pkgs.gnutar pkgs.gzip  # auth-toolchain's download fallback
              pkgs.git pkgs.cacert
              pkgs.ripgrep              # release bundle ELF validation
              pkgs.sccache             # opt-in shared compiler cache, see shellHook
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.file pkgs.binutils  # static-binary linkage checks (file, readelf)
              pkgs.util-linux          # prlimit for the key-memory check
            ];
            # Opt-in compiler cache shared by every job on a build machine (#329). The machine
            # sets INFRATERNAL_SCCACHE_DIR; with it unset (CI, releases, laptops) nothing changes
            # and no wrapper is installed. The cache only stores compiler outputs keyed by their
            # exact inputs, so a hit is byte-identical to a rebuild (proof on #329); it adds
            # nothing to any shipped artifact. The size cap bounds the disk it may use.
            shellHook = ''
              if [ -n "''${INFRATERNAL_SCCACHE_DIR:-}" ]; then
                export SCCACHE_DIR="$INFRATERNAL_SCCACHE_DIR"
                export SCCACHE_CACHE_SIZE="''${INFRATERNAL_SCCACHE_SIZE:-30G}"
                export RUSTC_WRAPPER=sccache
              fi
            '';
          };
        });
    };
}
