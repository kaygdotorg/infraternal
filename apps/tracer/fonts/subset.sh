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
fetch jb       https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip 6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf
fetch cm       https://github.com/eigilnikolajsen/commit-mono/releases/download/v1.143/CommitMono-1.143.zip f7d1f26a7c7554800a996f76f5d706bf0648b936ca2a66b5bc4d46e3a2c49ed0
fetch mona     https://github.com/githubnext/monaspace/releases/download/v1.400/monaspace-variable-v1.400.zip b69a7f2a3c455c89dcb6cc23b61bb3fb8beecba728ccdebeccd80577e58de0c8
fetch plex     "https://github.com/IBM/plex/releases/download/%40ibm%2Fplex-mono-variable%401.0.0/plex-mono-variable.zip" 46bbde4aeab959180ebad197f5b841c6bb5c8070146ba02c31240556e1e0b40d
fetch fira     https://github.com/tonsky/FiraCode/releases/download/6.2/Fira_Code_v6.2.zip 0949915ba8eb24d89fd93d10a7ff623f42830d7c5ffc3ecbf960e4ecad3e3e79
fetch scp      "https://github.com/adobe-fonts/source-code-pro/releases/download/2.042R-u%2F1.062R-i%2F1.026R-vf/VF-source-code-VF-1.026R.zip" 0660ba0cd1478f92cfcf2ad790b7aa29f8adb2daf15598f452a65ae61c9c9fb1
# Cascadia Code is a 150 MB archive; only its two variable TrueType files are read.
curl -fsSL -o "$work/cascadia.zip" https://github.com/microsoft/cascadia-code/releases/download/v2407.24/CascadiaCode-2407.24.zip
echo "e67a68ee3386db63f48b9054bd196ea752bc6a4ebb4df35adce6733da50c8474  $work/cascadia.zip" | sha256sum --check --quiet
mkdir -p "$work/src/cascadia"
unzip -q -o "$work/cascadia.zip" 'ttf/CascadiaCode.ttf' 'ttf/CascadiaCodeItalic.ttf' -d "$work/src/cascadia"

# Geist Mono comes from the locked npm package (version in bun.lock), not a download.
mkdir -p "$work/src/geist"
cp ../node_modules/geist/dist/fonts/geist-mono/GeistMono-Variable.ttf "$work/src/geist/"
cp "../node_modules/geist/dist/fonts/geist-mono/GeistMono-Italic[wght].ttf" "$work/src/geist/"

python3 subset.py "$work/src" "$here"

symbols="U+E000-E00A,U+E0A0-E0D7,U+E5FA-E6B7,U+E700-E7C5,U+F000-F2E0,U+F300-F381,U+F400-F532"
pyftsubset "$work/src/maplenf/MapleMono-NF-Regular.ttf" --unicodes="$symbols" --layout-features="" \
  --no-hinting --flavor=woff2 --output-file="$here/nerd-symbols.woff2"
