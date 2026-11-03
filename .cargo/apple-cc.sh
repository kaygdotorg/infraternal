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
# APPLE_CC_TOOL=clang++ selects the C++ driver (see apple-cxx.sh); no other
# value is accepted. TOOLCHAINS is dropped too: xcrun would otherwise pick a
# toolchain from a user-writable ~/Library/Developer/Toolchains.
#
# After every link, the output's dylib and rpath load commands must name only
# /usr/lib/ or /System/Library/. Anything else (a Homebrew prefix, @rpath, a
# store path) would let a root daemon load code that a user can replace, so
# the link fails and its output is removed.
set -eu
unset SDKROOT DEVELOPER_DIR TOOLCHAINS LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH
for name in $(env | sed -n 's/^\(NIX_[A-Za-z0-9_]*\)=.*/\1/p'); do
    unset "$name"
done
case ${APPLE_CC_TOOL:-clang} in
    clang | clang++) tool="/usr/bin/${APPLE_CC_TOOL:-clang}" ;;
    *)
        printf 'apple-cc.sh: APPLE_CC_TOOL must be clang or clang++\n' >&2
        exit 2
        ;;
esac
# A compile-only call (-c, -S, -E, -M*) produces no linked image to check.
links=yes
output=
expect_output=no
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
    if [ "$expect_output" = yes ]; then
        expect_output=no
        output=$argument
    fi
    case $argument in
        -c | -S | -E | -M | -MM) links=no ;;
        -o) expect_output=yes ;;
        -o?*) output=${argument#-o} ;;
        # rustc moves a long link line into a response file, one argument per line.
        @?*)
            if [ -f "${argument#@}" ]; then
                listed=$(/usr/bin/awk 'previous == "-o" || previous == "\"-o\"" { print; exit } { previous = $0 }' "${argument#@}")
                listed=${listed#\"}
                output=${listed%\"}
            fi
            ;;
    esac
    case $argument in
        -isysroot) skip=1 ;;
        -isysroot/nix/store/* | -isysroot=/nix/store/* | -Wl,-syslibroot,/nix/store/*) ;;
        *) set -- "$@" "$argument" ;;
    esac
done
if [ "$links" = no ] || [ -z "$output" ]; then
    exec "$tool" "$@"
fi
"$tool" "$@"
case $(/usr/bin/otool -hv "$output" 2>/dev/null) in
    *EXECUTE* | *DYLIB* | *BUNDLE*) ;;
    *) exit 0 ;;
esac
# Print "<command> <path>" for every load command that makes dyld open a file.
outside=$(/usr/bin/otool -l "$output" | /usr/bin/awk '
    $1 == "cmd" { command = $2; next }
    ($1 == "name" && command ~ /^LC_(LOAD|LOAD_WEAK|REEXPORT|LAZY_LOAD|LOAD_UPWARD)_DYLIB$/) ||
    ($1 == "path" && command == "LC_RPATH") {
        path = $0
        sub(/^ *(name|path) /, "", path)
        sub(/ \(offset [0-9]+\)$/, "", path)
        if (path !~ /^\/usr\/lib\// && path !~ /^\/System\/Library\//) print command, path
    }')
if [ -n "$outside" ]; then
    printf 'apple-cc.sh: %s loads code from outside the OS:\n%s\n' "$output" "$outside" >&2
    rm -f "$output"
    exit 1
fi
