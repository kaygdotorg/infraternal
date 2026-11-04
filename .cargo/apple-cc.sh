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
# After every link, the output must load only OS libraries:
# apple-image-check.sh has the rule. Any other file would let a root daemon
# load code that a user can replace, so the link fails and its output is
# removed.
#
# The output is found by asking clang, not by parsing the arguments: `clang
# -###` prints the exact jobs a call would run, after clang has expanded
# response files (nested ones too) and passed -Wl,/-Xlinker options to ld. A
# call whose jobs include a link must name exactly one ld output, and every
# job must be one this check understands; anything else fails closed. That
# covers a link without -o (a.out), `-o<path>` in a response file and
# `-Wl,-o,<path>` (J162's review of #265, F2).
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
here=$(cd "$(dirname -- "$0")" && pwd)
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
# Every call is listed, compiles included: spotting -c in the arguments is not
# enough, because `-o -c` or `-Xlinker -c` makes it a value and the call links.
# Each job line is a list of double-quoted words with backslash escapes. Print
# "output <path>" for each ld -o, "job <name>" for any job that is not a
# compile, an assemble, ld or dsymutil, and "file" when ld would read its own
# response file (whose -o this listing cannot see).
jobs=$("$tool" -### "$@" 2>&1) || {
    printf '%s\n' "$jobs" >&2
    exit 1
}
plan=$(printf '%s\n' "$jobs" | /usr/bin/awk '
    /^ "/ {
        split("", words); count = 0; word = ""; inside = 0; escaped = 0
        for (i = 1; i <= length($0); i++) {
            c = substr($0, i, 1)
            if (escaped) { word = word c; escaped = 0; continue }
            if (inside && c == "\\") { escaped = 1; continue }
            if (c == "\"") {
                if (inside) { words[++count] = word; word = "" }
                inside = !inside
                continue
            }
            if (inside) word = word c
        }
        tool = words[1]; sub(/.*\//, "", tool)
        if (words[2] == "-cc1" || words[2] == "-cc1as" || tool == "dsymutil") next
        if (tool != "ld") { print "job", tool; next }
        for (i = 2; i <= count; i++) {
            if (words[i] == "-o" && i < count) print "output", words[++i]
            # "@rpath/..." is an ordinary value; ld reads an @file only if it exists.
            else if (words[i] ~ /^@/ && (getline probe < substr(words[i], 2)) >= 0) print "file", words[i]
        }
    }')
case $plan in
    "") exec "$tool" "$@" ;;
esac
outputs=$(printf '%s\n' "$plan" | /usr/bin/sed -n 's/^output //p')
if printf '%s\n' "$plan" | /usr/bin/grep -q -v '^output ' ||
    [ "$(printf '%s\n' "$outputs" | /usr/bin/grep -c .)" -ne 1 ]; then
    printf 'apple-cc.sh: refusing a link whose output cannot be checked:\n%s\n' "$plan" >&2
    exit 1
fi
"$tool" "$@"
if ! "$here/apple-image-check.sh" "$outputs"; then
    rm -f -- "$outputs"
    exit 1
fi
