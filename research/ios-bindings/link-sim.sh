#!/usr/bin/env bash
# Links and runs the J1158 prototypes for the iOS Simulator, and links the
# iOS device executables for their size (#580).
#
# Runs on a Mac with Xcode (std), from a directory holding what build-mac.sh
# wrote: gen/, ios-libs/, ios-sim-libs/, plus this repo's swift/ and
# ne-memory/sim-main.c. Hold the simulator lock while it runs:
#   lockf -k /tmp/infraternal-std-sim.lock ./link-sim.sh <dir> <simulator-udid>
# Nothing is installed: the executables run inside the booted simulator with
# `simctl spawn`, and only talk to each other over 127.0.0.1.
set -euo pipefail
dir="$1"; sim="$2"
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$dir"; mkdir -p bin
gen="$dir/gen"
for plat in sim dev; do
  if [[ $plat == sim ]]; then sdk=iphonesimulator; triple=arm64-apple-ios17.0-simulator; libs="$dir/ios-sim-libs"
  else sdk=iphoneos; triple=arm64-apple-ios17.0; libs="$dir/ios-libs"; fi
  sc=(xcrun -sdk "$sdk" swiftc -target "$triple" -O -parse-as-library)
  "${sc[@]}" -o "bin/bench-baseline-$plat" "$here/swift/common.swift" "$here/swift/bench_baseline.swift"
  "${sc[@]}" -import-objc-header "$gen/uniffi/uniffi_coreFFI.h" -o "bin/bench-uniffi-$plat" \
    "$here/swift/common.swift" "$here/swift/bench_uniffi.swift" "$gen/uniffi/uniffi_core.swift" "$libs/libuniffi_core.a"
  "${sc[@]}" -import-objc-header "$gen/bridge/bridging.h" -o "bin/bench-bridge-$plat" \
    "$here/swift/common.swift" "$here/swift/bench_bridge.swift" "$gen/bridge/SwiftBridgeCore.swift" "$gen/bridge/bridge-core/bridge-core.swift" "$libs/libbridge_core.a"
  "${sc[@]}" -import-objc-header "$gen/cabi/cabi_core.h" -o "bin/bench-cabi-$plat" \
    "$here/swift/common.swift" "$here/swift/bench_cabi.swift" "$libs/libcabi_core.a"
  xcrun -sdk "$sdk" clang -target "$triple" -O2 -o "bin/ne-memory-$plat" "$here/ne-memory/sim-main.c" "$libs/libne_memory.a" -liconv
  for b in baseline uniffi bridge cabi; do xcrun strip -x -o "bin/bench-$b-$plat.stripped" "bin/bench-$b-$plat"; done
  xcrun strip -x -o "bin/ne-memory-$plat.stripped" "bin/ne-memory-$plat"
done
stat -f '%z %N' bin/*.stripped > sizes-ios.txt
for b in uniffi bridge cabi; do xcrun simctl spawn "$sim" "$dir/bin/bench-$b-sim" > "calls-sim-$b.jsonl"; done
rm -f ne-memory-sim.jsonl
for p in 0 50 500; do
  xcrun simctl spawn "$sim" "$dir/bin/ne-memory-sim" --peers "$p" --secs 20 --idle 10 >> ne-memory-sim.jsonl
done
xcrun simctl spawn "$sim" "$dir/bin/ne-memory-sim" --peers 50 --window 2048 --secs 20 --idle 10 >> ne-memory-sim.jsonl
echo DONE
