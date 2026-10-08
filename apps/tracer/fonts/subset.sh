#!/usr/bin/env bash
# Rebuilds the self-hosted Maple Mono NF subsets in this directory.
#
# Source: the official Maple Mono NF release v7.9 (SIL OFL 1.1, see
# OFL-LICENSE.txt). The archive is verified against the release checksum, then
# each face is cut down to the ranges below and written as woff2. The unicode
# ranges here MUST match the `unicode-range` descriptors in ../style.css: a
# face that claims a range it does not contain makes the browser fall through
# to a different font mid-line.
#
#   latin    Latin, punctuation, arrows, a few keyboard/maths symbols, box
#            drawing, blocks, geometric shapes, check marks, braille. Four
#            weights/styles plus semibold italic for terminal bold italic.
#   symbols  Nerd Font ranges for shell prompts (powerline, seti, devicons,
#            Font Awesome, distro logos, octicons). One regular face: icon
#            glyphs do not change with weight and every one is a single cell.
#
# Needs: python3 with fonttools and brotli (pip install fonttools brotli), curl.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
release=v7.9
sha=59098b87c895d871635d37680e88000ae2b2b25b55428195b228ec589e35fb89
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/nf.zip" "https://github.com/subframe7536/maple-font/releases/download/$release/MapleMono-NF.zip"
echo "$sha  $work/nf.zip" | sha256sum --check --quiet
unzip -q "$work/nf.zip" -d "$work/nf"

latin="U+0020-007E,U+00A0-00FF,U+0131,U+0152-0153,U+0160-0161,U+0178,U+017D-017E,U+02C6,U+02DC,U+2000-206F,U+20AC,U+2122,U+2190-21FF,U+2212,U+2215,U+221A,U+221E,U+2248,U+2260-2265,U+2303,U+2318,U+2325-2326,U+232B,U+238B,U+23CE,U+2500-25FF,U+2713-2717,U+2800-28FF"
symbols="U+E000-E00A,U+E0A0-E0D7,U+E5FA-E6B7,U+E700-E7C5,U+F000-F2E0,U+F300-F381,U+F400-F532"
# calt carries the programming ligatures; ccmp and locl are needed for combining marks.
features="calt,ccmp,locl"
for face in Regular Medium SemiBold Italic SemiBoldItalic; do
  pyftsubset "$work/nf/MapleMono-NF-$face.ttf" --unicodes="$latin" --layout-features="$features" \
    --no-hinting --notdef-outline --flavor=woff2 --output-file="MapleMonoNF-$face.latin.woff2"
done
pyftsubset "$work/nf/MapleMono-NF-Regular.ttf" --unicodes="$symbols" --layout-features="" \
  --no-hinting --flavor=woff2 --output-file="MapleMonoNF-symbols.woff2"
