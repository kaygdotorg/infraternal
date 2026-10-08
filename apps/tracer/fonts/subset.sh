#!/usr/bin/env bash
# Rebuilds the self-hosted font subsets in this directory (D87, D175).
#
# Every family is SIL OFL 1.1 and its licence text sits in its own directory. Each
# upstream archive is verified against a pinned checksum, then subset.py cuts every face
# down to the Unicode ranges in packages/ui/src/fonts.ts and writes woff2. Those ranges MUST
# match the `unicode-range` descriptors in ../style.css: a face that claims a range it does
# not contain makes the browser fall through to a different font in the middle of a line.
#
#   <family>/roman.latin.woff2, italic.latin.woff2
#            One variable face per style with the weight axis cut to 400-700 (Commit Mono
#            ships two static weights, so it has four files).
#   nerd-symbols.woff2
#            Nerd Font ranges for shell prompts (powerline, seti, devicons, Font Awesome,
#            distro logos, octicons), taken from the Maple Mono NF release. One regular
#            face: icon glyphs do not change with weight and every one is a single cell.
#            It is the fallback for every family, so prompts look right whichever font is
#            chosen.
#
# Needs: python3 with fonttools and brotli (pip install fonttools brotli), curl, unzip, and
# `bun install` in ../ (the Geist Mono source is the locked `geist` package).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
here="$PWD"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

fetch() { # name url sha256 -> extracts to $work/src/<name>
  curl -fsSL -o "$work/$1.zip" "$2"
  echo "$3  $work/$1.zip" | sha256sum --check --quiet
  mkdir -p "$work/src/$1"
  unzip -q -o "$work/$1.zip" -d "$work/src/$1" -x '__MACOSX/*' || true
}

fetch maple    https://github.com/subframe7536/maple-font/releases/download/v7.9/MapleMono-Variable.zip b9e57677cc4ec069ce178bd965d66cd14bd26c12e37d89d786ff959339bf8c93
fetch maplenf  https://github.com/subframe7536/maple-font/releases/download/v7.9/MapleMono-NF.zip 59098b87c895d871635d37680e88000ae2b2b25b55428195b228ec589e35fb89
python3 subset.py "$work/src" "$here"

symbols="U+E000-E00A,U+E0A0-E0D7,U+E5FA-E6B7,U+E700-E7C5,U+F000-F2E0,U+F300-F381,U+F400-F532"
pyftsubset "$work/src/maplenf/MapleMono-NF-Regular.ttf" --unicodes="$symbols" --layout-features="" \
  --no-hinting --flavor=woff2 --output-file="$here/nerd-symbols.woff2"
