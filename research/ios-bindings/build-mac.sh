#!/usr/bin/env bash
# Builds and runs the J1158 prototypes on the Mac build VM (#580).
#
# Run from this directory on the Mac, under the shared Mac lock:
#   lockf -k /tmp/mac-bench.lock ./build-mac.sh <sdk-dir> <out-dir>
# <sdk-dir> holds iPhoneOS.sdk and iPhoneSimulator.sdk copied from a Mac
# with Xcode (the Mac VM has only the Command Line Tools). The script:
#   1. builds the three binding libraries for arm64 macOS, iOS and the iOS
#      Simulator, and ne-memory for macOS and the Simulator;
#   2. generates the Swift glue (UniFFI, swift-bridge, cbindgen);
#   3. links and runs the macOS benchmarks and ne-memory;
#   4. writes sizes and results to <out-dir>.
# The iOS Simulator executables are linked on a Mac with Xcode by
# link-sim.sh, because Swift's iOS libraries ship only with Xcode.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
sdk="$1"; out="$2"
mkdir -p "$out"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$here/../target}" CARGO_INCREMENTAL=0
export IPHONEOS_DEPLOYMENT_TARGET=17.0
libs=(-p uniffi-core -p bridge-core -p cabi-core)
# Nix's shell puts its own clang wrapper first in PATH; C build scripts and
# the linker must use Apple's Command Line Tools for every Apple target.
# clang reads SDKROOT itself, so host links (build scripts, macOS) go through
# mac-cc.sh, which drops an iOS SDKROOT. iOS targets are built as static
# libraries only: this Mac's linker is older than the iOS 27.2 SDK's stubs.
# GotaTun also declares a cdylib, which cargo links even as a dependency, so
# the iOS targets get ios-skip-cc.sh, which skips that unused link.
apple_cc=(CC=/usr/bin/clang AR=/usr/bin/ar "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=$here/mac-cc.sh"
  "CARGO_TARGET_AARCH64_APPLE_IOS_LINKER=$here/ios-skip-cc.sh" "CARGO_TARGET_AARCH64_APPLE_IOS_SIM_LINKER=$here/ios-skip-cc.sh")
cargo_in_shell() { nix develop "$here" -c env "${apple_cc[@]}" "$@"; }

# 1. Builds. Apple C build scripts (ring) find their SDK through SDKROOT.
start=$(date +%s)
cargo_in_shell cargo build --release --target aarch64-apple-darwin "${libs[@]}" -p ne-memory
cargo_in_shell cargo build --release --target aarch64-apple-darwin -p uniffi-core --bin uniffi-bindgen
echo "darwin build: $(( $(date +%s) - start )) s" | tee "$out/build-times.txt"
for t in aarch64-apple-ios:iPhoneOS aarch64-apple-ios-sim:iPhoneSimulator; do
  start=$(date +%s)
  for p in uniffi-core bridge-core cabi-core ne-memory; do
    cargo_in_shell SDKROOT="$sdk/${t#*:}.sdk" cargo rustc --release --target "${t%%:*}" -p "$p" --lib --crate-type staticlib
  done
  echo "${t%%:*} build: $(( $(date +%s) - start )) s" | tee -a "$out/build-times.txt"
done

# 2. Generated glue.
gen="$out/gen"; rm -rf "$gen"; mkdir -p "$gen/uniffi" "$gen/cabi"
cargo_in_shell "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/uniffi-bindgen" generate \
  --library "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/libuniffi_core.dylib" --language swift --out-dir "$gen/uniffi"
cp -R "$here/bridge-core/generated" "$gen/bridge"
cp "$here/cabi-core/include/cabi_core.h" "$gen/cabi/"
printf '#include "SwiftBridgeCore.h"\n#include "bridge-core/bridge-core.h"\n' > "$gen/bridge/bridging.h"
wc -l "$gen"/uniffi/* "$gen"/bridge/*.swift "$gen"/bridge/*/* "$gen"/cabi/* > "$out/generated-lines.txt"

# 3. macOS benchmarks, each linking one static library.
rel="$CARGO_TARGET_DIR/aarch64-apple-darwin/release"
swiftc -O -parse-as-library -o "$out/bench-baseline" "$here/swift/common.swift" "$here/swift/bench_baseline.swift"
swiftc -O -parse-as-library -import-objc-header "$gen/uniffi/uniffi_coreFFI.h" -o "$out/bench-uniffi" \
  "$here/swift/common.swift" "$here/swift/bench_uniffi.swift" "$gen/uniffi/uniffi_core.swift" "$rel/libuniffi_core.a"
swiftc -O -parse-as-library -import-objc-header "$gen/bridge/bridging.h" -o "$out/bench-bridge" \
  "$here/swift/common.swift" "$here/swift/bench_bridge.swift" "$gen/bridge/SwiftBridgeCore.swift" "$gen/bridge/bridge-core/bridge-core.swift" "$rel/libbridge_core.a"
swiftc -O -parse-as-library -import-objc-header "$gen/cabi/cabi_core.h" -o "$out/bench-cabi" \
  "$here/swift/common.swift" "$here/swift/bench_cabi.swift" "$rel/libcabi_core.a"
for b in baseline uniffi bridge cabi; do strip -x -o "$out/bench-$b.stripped" "$out/bench-$b"; done
{
  echo "# stripped macOS executables (bytes)"; stat -f '%z %N' "$out"/bench-*.stripped
  echo "# static libraries (bytes)"
  for t in aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim; do
    stat -f "%z $t %N" "$CARGO_TARGET_DIR/$t/release/"lib{uniffi,bridge,cabi}_core.a
  done
  echo "# ne-memory: macOS executable, iOS static libraries (bytes)"
  stat -f '%z %N' "$CARGO_TARGET_DIR"/aarch64-apple-darwin/release/ne-memory "$CARGO_TARGET_DIR"/aarch64-apple-{ios,ios-sim}/release/libne_memory.a
} > "$out/sizes.txt"
for b in uniffi bridge cabi; do "$out/bench-$b" > "$out/calls-macos-$b.jsonl"; done

# 4. ne-memory on macOS: 0 / 50 / 500 idle peers with 256 packets in
# flight, then 2048 in flight (deeper queues), 1280-byte packets.
rm -f "$out/ne-memory-macos.jsonl"
for p in 0 50 500; do
  "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/ne-memory" --peers "$p" --secs 20 --idle 10 >> "$out/ne-memory-macos.jsonl"
done
"$CARGO_TARGET_DIR/aarch64-apple-darwin/release/ne-memory" --peers 50 --window 2048 --secs 20 --idle 10 >> "$out/ne-memory-macos.jsonl"
for t in ios ios-sim; do
  mkdir -p "$out/$t-libs"; cp "$CARGO_TARGET_DIR"/aarch64-apple-$t/release/lib{uniffi,bridge,cabi,ne}_*.a "$out/$t-libs/"
done
echo DONE
