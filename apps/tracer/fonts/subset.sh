#!/usr/bin/env bash
# Rebuilds the self-hosted font subsets in this directory (D87, D175).
#
# Every family is SIL OFL 1.1 (Hack: MIT with the Bitstream Vera licence) and its licence text sits in its own directory. Each
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
# D329 (#323). The archives are large or hold many weights, so only the files read are extracted (selective unzip).
pick() { # name url sha256 file... -> extracts only those files to $work/src/<name>
  local name=$1 url=$2 sum=$3; shift 3
  curl -fsSL -o "$work/$name.zip" "$url"
  echo "$sum  $work/$name.zip" | sha256sum --check --quiet
  mkdir -p "$work/src/$name"
  unzip -q -o "$work/$name.zip" "$@" -d "$work/src/$name"
}
pick iosevka https://github.com/be5invis/Iosevka/releases/download/v34.9.1/PkgTTF-Iosevka-34.9.1.zip 7a77a3dfa0e2d713a8920a30624863e23df2867a1f55a5e3d6d23dad07c14c65 Iosevka-Regular.ttf Iosevka-Bold.ttf Iosevka-Italic.ttf Iosevka-BoldItalic.ttf
pick victor https://github.com/rubjo/victor-mono/raw/v1.5.6/public/VictorMonoAll.zip eab377ad3bcc7a202697c024ebb8c8728f99789c4f093d358f3d202052cc9496 TTF/VictorMono-Regular.ttf TTF/VictorMono-Bold.ttf TTF/VictorMono-Italic.ttf TTF/VictorMono-BoldItalic.ttf
pick recursive https://github.com/arrowtype/recursive/releases/download/v1.085/ArrowType-Recursive-1.085.zip cbcbdf7a0e181d284a9235e09ed5f3873e527bc5dd1d977df71cdc1ff937da02 ArrowType-Recursive-1.085/Recursive_Desktop/Recursive_VF_1.085.ttf
pick martianvf https://github.com/evilmartians/mono/releases/download/v1.1.0/martian-mono-1.1.0-variable.zip b87730975931dc2dbf0129ecf392ccaf8d29f46bc05e995703da4155db510867 MartianMonoVF.ttf
pick intel https://github.com/intel/intel-one-mono/releases/download/V1.4.0/ttf.zip 54863552d25dcb9c3f5360b296fc980d6e1fbfd02e0d214224e8b78f0a2bccf0 ttf/IntelOneMono-Regular.ttf ttf/IntelOneMono-Bold.ttf ttf/IntelOneMono-Italic.ttf ttf/IntelOneMono-BoldItalic.ttf
pick fantasque https://github.com/belluzj/fantasque-sans/releases/download/v1.8.0/FantasqueSansMono-Normal.zip 84be689e231ff773ed9d352e83dccd8151d9e445f1cb0b88cb0e9330fc4d9cfc TTF/FantasqueSansMono-Regular.ttf TTF/FantasqueSansMono-Bold.ttf TTF/FantasqueSansMono-Italic.ttf TTF/FantasqueSansMono-BoldItalic.ttf
pick hack https://github.com/source-foundry/Hack/releases/download/v3.003/Hack-v3.003-ttf.zip 0c2604631b1f055041c68a0e09ae4801acab6c5072ba2db6a822f53c3f8290ac ttf/Hack-Regular.ttf ttf/Hack-Bold.ttf ttf/Hack-Italic.ttf ttf/Hack-BoldItalic.ttf
pick oxproto https://github.com/0xType/0xProto/releases/download/2.502/0xProto_2_502.zip 402d046b6056111ae5b974892fe2d6d921c66a64681980ec81db051de05851e7 fonts/0xProto-Regular.ttf fonts/0xProto-Bold.ttf fonts/0xProto-Italic.ttf
pick lilex https://github.com/mishamyrt/Lilex/releases/download/2.630/Lilex.zip c946bf022f22895799eb69bcc5f2318ed4089e4e34b90054dfd78ed5316728e0 'variable/Lilex[wght].ttf' 'variable/Lilex-Italic[wght].ttf'
mkdir -p "$work/src/inconsolata"
curl -fsSL -o "$work/src/inconsolata/Inconsolata-VF.ttf" https://github.com/googlefonts/Inconsolata/releases/download/v3.000/Inconsolata-VF.ttf
echo "33dd95333e9e51ed75c18ccd340f4f7166773ff5303ddedb9d084a623f829d08  $work/src/inconsolata/Inconsolata-VF.ttf" | sha256sum --check --quiet

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
