#!/bin/sh
# (Named "-cc", not "-ld": rustc picks the linker flavour from the name.)
# Links for the host (macOS) with Apple's clang, ignoring an iOS SDKROOT that
# the same cargo run sets for the iOS target's C build scripts.
unset SDKROOT
exec /usr/bin/clang "$@"
