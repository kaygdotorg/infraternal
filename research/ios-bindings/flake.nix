# Toolchain for the iOS bindings prototypes (J1158, #580).
#
# Same nixpkgs and rust-overlay pins as the repository flake (flake.lock is a
# copy of the root lock), plus the three Apple standard libraries the client
# core needs: arm64 macOS, arm64 iOS devices and the arm64 iOS Simulator.
# `mkShellNoCC` keeps nix's clang wrapper and Apple SDK out of PATH, so C
# build scripts (ring) and the linker use the machine's own Command Line Tools
# with SDKROOT pointing at an iOS SDK. Nix cannot ship Apple's iOS SDK itself.
{
  description = "infraternal iOS bindings prototypes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      pkgs = import nixpkgs { system = "aarch64-darwin"; overlays = [ rust-overlay.overlays.default ]; };
      # The workspace's pinned compiler, with Apple targets instead of musl.
      rust = pkgs.rust-bin.stable."1.99.1".minimal.override {
        targets = [ "aarch64-apple-darwin" "aarch64-apple-ios" "aarch64-apple-ios-sim" ];
      };
      # The repository Cargo config asks rustup which compiler to use. Nix
      # already pinned it above, so answer that query without downloading one.
      rustupShim = pkgs.writeShellScriptBin "rustup" ''
        if [ "$1" = which ] && [ -n "$2" ]; then
          command -v "$2"
          exit
        fi
        echo "rustup shim: only 'rustup which <tool>' is supported (nix provides the toolchain)" >&2
        exit 1
      '';
    in {
      devShells.aarch64-darwin.default = pkgs.mkShellNoCC { packages = [ rust rustupShim ]; };
    };
}
