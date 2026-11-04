#!/bin/sh
# Refuse a macOS image that would make dyld load code from outside the OS (#265).
#
# Usage: apple-image-check.sh FILE...
# Exit 0 when every FILE passes, 1 when one is refused, 2 when one cannot be
# inspected. A missing file, a missing or failing otool and an unparsable
# listing all refuse: the check never passes by default.
#
# A root LaunchDaemon starts before any user-installed volume mounts, and dyld
# runs its load commands as root, so every file they name must be one that
# ships with macOS:
# - dylib loads and LC_RPATH entries are absolute paths under /usr/lib/ or
#   /System/Library/, with no "." or ".." component (dyld resolves
#   /usr/lib/../../private/tmp/x to a user-writable file);
# - LC_DYLD_ENVIRONMENT is refused: -dyld_env stores DYLD_* variables, such
#   as a library search path, inside the binary;
# - LC_LOAD_DYLINKER, when present, is exactly /usr/lib/dyld.
# crates/plugins/mesh/src/macos_image.rs applies the same rule at `mesh install`
# without otool, which a Mac without the command-line tools lacks.
set -eu
otool=/usr/bin/otool
if [ "$#" -eq 0 ]; then
    printf 'usage: apple-image-check.sh FILE...\n' >&2
    exit 2
fi
for image in "$@"; do
    # A file named like an option must not reach otool as one.
    case $image in
        -*) image=./$image ;;
    esac
    if [ ! -f "$image" ]; then
        printf 'apple-image-check.sh: %s: no such file to check\n' "$image" >&2
        exit 2
    fi
    if ! listing=$("$otool" -l "$image" 2>/dev/null); then
        printf 'apple-image-check.sh: %s: otool could not read the load commands\n' "$image" >&2
        exit 2
    fi
    # Print "<command> <path>" for every load command that is not allowed, and
    # "commands <n>" so an empty listing is not mistaken for a clean one.
    verdict=$(printf '%s\n' "$listing" | /usr/bin/awk '
        function outside_os(path,    count, parts, index_) {
            if (path !~ /^\/usr\/lib\// && path !~ /^\/System\/Library\//) return 1
            count = split(path, parts, "/")
            for (index_ = 1; index_ <= count; index_++)
                if (parts[index_] == "." || parts[index_] == "..") return 1
            return 0
        }
        $1 == "cmd" {
            command = $2
            commands++
            if (command == "LC_DYLD_ENVIRONMENT") print command, "(refused)"
            next
        }
        $1 == "name" || $1 == "path" {
            path = $0
            sub(/^ *(name|path) /, "", path)
            sub(/ \(offset [0-9]+\)$/, "", path)
            if ($1 == "name" && command ~ /^LC_(LOAD|LOAD_WEAK|REEXPORT|LAZY_LOAD|LOAD_UPWARD)_DYLIB$/ && outside_os(path)) print command, path
            if ($1 == "path" && command == "LC_RPATH" && outside_os(path)) print command, path
            if ($1 == "name" && command == "LC_LOAD_DYLINKER" && path != "/usr/lib/dyld") print command, path
        }
        END { print "commands", commands + 0 }')
    case $verdict in
        "commands 0" | "")
            printf 'apple-image-check.sh: %s: no load commands listed\n' "$image" >&2
            exit 2
            ;;
        "commands "*) ;;
        *)
            printf 'apple-image-check.sh: %s loads code from outside the OS:\n%s\n' \
                "$image" "$(printf '%s\n' "$verdict" | /usr/bin/sed '$d')" >&2
            exit 1
            ;;
    esac
done
