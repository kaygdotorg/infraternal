#!/bin/sh
# C++ driver for macOS targets; same OS-only toolchain rules as apple-cc.sh (#265).
APPLE_CC_TOOL=clang++ exec "$(dirname -- "$0")/apple-cc.sh" "$@"
