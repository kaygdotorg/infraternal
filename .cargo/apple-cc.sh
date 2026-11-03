#!/bin/sh
# Compile and link macOS targets with the OS toolchain and SDK only (#265).
#
# A root LaunchDaemon starts before any user-installed volume mounts, so the
# binary may reference only libraries that ship with macOS. The repository's
# development shell exports its own SDK (SDKROOT, DEVELOPER_DIR) and NIX_*
# compiler flags. /usr/bin/clang is a toolchain shim that honours those
# variables, and rustc forwards SDKROOT as -isysroot, so without this wrapper
# the daemon linked the shell's libiconv from /nix/store and failed in dyld for
# the first ~50 s after every boot. This wrapper drops that environment and any
# /nix/store sysroot argument, then runs the toolchain selected by xcode-select.
# APPLE_CC_TOOL=clang++ selects the C++ driver (see apple-cxx.sh).
set -eu
unset SDKROOT DEVELOPER_DIR LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH
for name in $(env | sed -n 's/^\(NIX_[A-Za-z0-9_]*\)=.*/\1/p'); do
    unset "$name"
done
tool="/usr/bin/${APPLE_CC_TOOL:-clang}"
# Rebuild "$@" without a store sysroot; every other argument passes unchanged.
count=$#
skip=0
while [ "$count" -gt 0 ]; do
    argument=$1
    shift
    count=$((count - 1))
    if [ "$skip" -eq 1 ]; then
        skip=0
        case $argument in
            /nix/store/*) continue ;;
            *) set -- "$@" -isysroot "$argument"; continue ;;
        esac
    fi
    case $argument in
        -isysroot) skip=1 ;;
        -isysroot/nix/store/* | -isysroot=/nix/store/* | -Wl,-syslibroot,/nix/store/*) ;;
        *) set -- "$@" "$argument" ;;
    esac
done
exec "$tool" "$@"
