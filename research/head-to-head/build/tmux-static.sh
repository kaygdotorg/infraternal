#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Build a fully static tmux for the head-to-head kit from pinned official
# source releases (tmux, libevent, ncurses), cross-compiled with the repo's
# pinned Zig C toolchain (D213). tmux publishes no official binaries, and the
# perf VM must not get packages installed, so this is the closest we get to
# "an official release": upstream's release tarball, unmodified, verified by
# SHA-256 before it is unpacked.
#
#   tmux-static.sh <zig> <x86_64|aarch64> <download-dir> <work-dir> <out-file>
#
# The build host needs a yacc for tmux's command grammar (YACC, default
# "bison -y"); the release tarball does not ship the generated parser.
#
# The terminfo search path is the Debian/Ubuntu default, so the binary finds
# xterm-256color in /lib/terminfo or /usr/share/terminfo on the perf VM.
set -euo pipefail
zig=$1 arch=$2 dl=$3 work=$4 out=$5
target="$arch-linux-musl"
declare -A pins=(
  [tmux-3.8.tar.gz]=e79c699c7e949dccd0a4a125e17b8d1261e311b16979dbc8eb34542f3966d82e
  [libevent-2.1.13-stable.tar.gz]=f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c
  [ncurses-6.5.tar.gz]=136d91bc269a9a5785e5f9e980bc76ab57428f604ce3e5a5a90cebc767971cc6
)
for file in "${!pins[@]}"; do
  printf '%s  %s\n' "${pins[$file]}" "$dl/$file" | sha256sum --check --status
done
rm -rf "$work"; mkdir -p "$work/src" "$work/prefix"
for file in "${!pins[@]}"; do tar -xzf "$dl/$file" -C "$work/src"; done
prefix="$work/prefix"
export CC="$zig cc -target $target" AR="$zig ar" RANLIB="$zig ranlib"
export CFLAGS="-O2" PKG_CONFIG_PATH="$prefix/lib/pkgconfig" PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
jobs=${CARGO_BUILD_JOBS:-4}
(cd "$work/src/libevent-2.1.13-stable" &&
  ./configure --host="$target" --prefix="$prefix" --disable-shared --enable-static \
    --disable-openssl --disable-samples --disable-libevent-regress --disable-debug-mode >/dev/null &&
  make -j"$jobs" >/dev/null && make install >/dev/null)
(cd "$work/src/ncurses-6.5" &&
  ./configure --host="$target" --prefix="$prefix" --with-build-cc=cc \
    --without-shared --without-debug --without-ada --without-cxx --without-cxx-binding \
    --without-progs --without-tests --without-manpages --enable-widec --enable-pc-files \
    --with-pkg-config-libdir="$prefix/lib/pkgconfig" \
    --with-default-terminfo-dir=/usr/share/terminfo \
    --with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo >/dev/null &&
  # Libraries and headers only: the terminfo database comes from the target host.
  make -j"$jobs" >/dev/null && make install.libs install.includes >/dev/null)
(cd "$work/src/tmux-3.8" &&
  ./configure --host="$target" --enable-static YACC="${YACC:-bison -y}" \
    CPPFLAGS="-I$prefix/include -I$prefix/include/ncursesw" LDFLAGS="-L$prefix/lib -s" \
    LIBEVENT_CORE_CFLAGS="-I$prefix/include" LIBEVENT_CORE_LIBS="-L$prefix/lib -levent_core" \
    LIBEVENT_CFLAGS="-I$prefix/include" LIBEVENT_LIBS="-L$prefix/lib -levent" \
    LIBTINFO_CFLAGS="-I$prefix/include/ncursesw" LIBTINFO_LIBS="-L$prefix/lib -lncursesw" >/dev/null &&
  make -j"$jobs" >/dev/null)
cp "$work/src/tmux-3.8/tmux" "$out"
