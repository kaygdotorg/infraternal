#!/bin/sh
# Stand-in "linker" for the iOS targets on a Mac without Xcode.
#
# This prototype only builds iOS *static* libraries, which rustc archives
# without a linker. GotaTun's manifest also declares a cdylib, and cargo links
# that even when GotaTun is only a dependency; this Mac's linker is older than
# the iOS 27.2 SDK's library stubs and fails on it. Nothing uses that dylib, so
# this writes an empty file at the -o path and says so. Never use it for a real
# iOS link: Xcode's toolchain links the Simulator executables (link-sim.sh).
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift; fi
  shift
done
echo "ios-skip-cc: skipped link of ${out##*/}" >&2
: > "$out"
