# Development shell: the whole toolchain `scripts/verify fast` needs, from nix.
#
# `nix develop` gives every build machine the same compiler (read from
# rust-toolchain.toml, so the toml stays the single source of truth), the same
# JS runtime and the same helper tools. Nothing is installed outside nix.
# This flake builds nothing of the product; it only provides tools.
#
# Not from nix: Zig 0.15.2. scripts/auth-toolchain downloads that exact
# checksum-pinned release into target/auth-tools, and the static C builds
# depend on the pin, so it stays there.
{
  description = "infraternal development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      # aarch64-darwin is included but untested; verify fast targets Linux.
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system:
        f (import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; }));
    in {
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
        in {
          default = pkgs.mkShell {
            packages = [
              rust rustupShim
              pkgs.cargo-deny          # cargo-deny gate (deny.toml)
              pkgs.bun                 # TypeScript tests, tracer build
              pkgs.nodejs              # JavaScript CLI shebangs in type checks
              pkgs.vim                 # Real-editor terminal repaint fixture
              pkgs.openssh             # Release-signature and SSH key fixtures
              pkgs.python3             # release and fixture scripts
              pkgs.gnumake pkgs.perl   # vendored OpenSSL build drivers
              pkgs.gcc                 # host-side build scripts and proc macros
              pkgs.curl pkgs.xz pkgs.gnutar pkgs.gzip  # scripts/auth-toolchain fetches Zig
              pkgs.git pkgs.cacert
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.file pkgs.binutils  # static-binary linkage checks (file, readelf)
              pkgs.util-linux          # prlimit for the key-memory check
            ];
          };
        });
    };
}
