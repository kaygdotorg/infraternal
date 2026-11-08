# The one pinned Zig (D213, D328): the same release tarball and SHA-256 that
# scripts/auth-toolchain downloads, fetched as a fixed-output derivation.
#
# scripts/zig.sha256 is the single checksum table for both paths, so the
# shell script and nix cannot pin different compilers. `archive` is the
# untouched tarball; `unpacked` is it extracted without changes, for the
# development shell. The release package (package.nix) applies its own
# sandbox patches on top of `archive`.
{ lib, stdenv, fetchurl, runCommand, xz }:
let
  version = "0.17.0";
  # Zig names hosts <cpu>-<os> with "macos", not nix's "darwin".
  host = {
    x86_64-linux = "x86_64-linux";
    aarch64-linux = "aarch64-linux";
    aarch64-darwin = "aarch64-macos";
  }.${stdenv.hostPlatform.system};
  file = "zig-${host}-${version}.tar.xz";
  # Lines are `sha256sum` output: "<hex>  <file>".
  pins = builtins.listToAttrs (map
    (line: let fields = lib.splitString "  " line; in {
      name = builtins.elemAt fields 1;
      value = builtins.elemAt fields 0;
    })
    (lib.filter (line: line != "") (lib.splitString "\n" (builtins.readFile ../scripts/zig.sha256))));
  archive = fetchurl {
    url = "https://ziglang.org/download/${version}/${file}";
    sha256 = pins.${file};
  };
in {
  inherit version archive;
  unpacked = runCommand "infraternal-zig-${version}-unpacked" { nativeBuildInputs = [ xz ]; } ''
    mkdir -p "$out"
    tar -xJf ${archive} --strip-components=1 -C "$out"
  '';
}
