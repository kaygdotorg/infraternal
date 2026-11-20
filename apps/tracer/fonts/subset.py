#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Cuts the self-hosted terminal and UI fonts down to latin woff2 (called by subset.sh).

Every family is SIL OFL 1.1 (Hack is MIT with the Bitstream Vera licence) and its licence text sits next to its output. For each one this
script reads the upstream variable (or static) TrueType file, narrows the weight axis to the
range the UI can ask for, pins every other axis, keeps only the Unicode ranges below and the
layout features the UI and terminal use, and writes woff2.

Why a variable axis limited to 400-700: the registry in packages/ui/src/fonts.ts picks a
body weight per family and derives label, title and bold weights from it. One variable face
serves all of them, replacing a static face per weight, and nothing the UI asks for lies
outside 400-700.

Families whose licence declares a Reserved Font Name get their internal family names
replaced: the OFL forbids a Modified Version (a subset is one) from using that name. The CSS
family names used in the page are our own aliases and are not affected.
"""
import io
import sys
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

# The Unicode ranges here MUST match `LATIN_RANGE` in packages/ui/src/fonts.ts and the
# `unicode-range` descriptors in ../style.css: a face that claims a range it does not contain
# makes the browser fall through to a different font in the middle of a line.
LATIN = (
    "U+0020-007E,U+00A0-00FF,U+0131,U+0152-0153,U+0160-0161,U+0178,U+017D-017E,U+02C6,U+02DC,"
    "U+2000-206F,U+20AC,U+2122,U+2190-21FF,U+2212,U+2215,U+221A,U+221E,U+2248,U+2260-2265,U+2303,"
    "U+2318,U+2325-2326,U+232B,U+238B,U+23CE,U+2500-25FF,U+2713-2717,U+2800-28FF"
)
# calt carries the programming ligatures; ccmp and locl are needed for combining marks.
FEATURES = ["calt", "liga", "ccmp", "locl", "rlig", "rclt"]
WEIGHT_RANGE = (400, 700)
RENAMED_IDS = (1, 3, 4, 6, 16, 17, 21, 22)  # family, unique id, full name, postscript, typographic names


def unicodes() -> list[int]:
    out: list[int] = []
    for part in LATIN.split(","):
        lo, _, hi = part.removeprefix("U+").partition("-U+" if "-U+" in part else "-")
        out.extend(range(int(lo, 16), int(hi or lo, 16) + 1))
    return out


def write(font: TTFont, target: Path, rename: str | None) -> None:
    options = subset.Options()
    options.layout_features = FEATURES
    options.hinting = False
    options.notdef_outline = True
    options.flavor = "woff2"
    options.name_IDs = [0, 1, 2, 3, 4, 5, 6, 13, 14]
    options.name_languages = [0x409]
    subsetter = subset.Subsetter(options)
    subsetter.populate(unicodes=unicodes())
    subsetter.subset(font)
    if rename:
        name = font["name"]
        for record in list(name.names):
            if record.nameID in RENAMED_IDS:
                name.removeNames(nameID=record.nameID)
        for name_id in (1, 4, 16):
            name.setName(rename, name_id, 3, 1, 0x409)
        name.setName(rename.replace(" ", "-"), 6, 3, 1, 0x409)
        name.setName(rename + " Subset", 3, 3, 1, 0x409)
    font.flavor = "woff2"
    target.parent.mkdir(parents=True, exist_ok=True)
    font.save(target)
    print(f"{target} {target.stat().st_size}")


def variable(source: Path, target: Path, pins: dict[str, float], rename: str | None) -> None:
    font = TTFont(source)
    limits: dict = dict(pins)
    low, high = WEIGHT_RANGE
    axis = next(a for a in font["fvar"].axes if a.axisTag == "wght")
    limits["wght"] = (low, min(max(axis.defaultValue, low), high), min(axis.maxValue, high))
    font = instancer.instantiateVariableFont(font, limits)
    # Reload through a buffer: the instancer leaves lazily loaded variation tables that the
    # subsetter cannot index by the glyph names it retains.
    buffer = io.BytesIO()
    font.save(buffer)
    write(TTFont(buffer), target, rename)


def static(source: Path, target: Path, rename: str | None) -> None:
    write(TTFont(source), target, rename)


def main() -> None:
    root = Path(sys.argv[1])  # directory the shell script extracted the upstream archives into
    out = Path(sys.argv[2])
    # Optional third argument: only these family ids (comma-separated). Adding a family must not rewrite the files of the others: a newer
    # fonttools writes different bytes for the same font, and the diff would bury the new files.
    only = set(sys.argv[3].split(",")) if len(sys.argv) > 3 else None
    # id: (roman source, italic source or None, pins for roman, pins for italic, rename)
    families = {
        "maple-mono-nf": ("maple/MapleMono[wght].ttf", "maple/MapleMono-Italic[wght].ttf", {}, {}, None),
        "geist-mono": ("geist/GeistMono-Variable.ttf", "geist/GeistMono-Italic[wght].ttf", {}, {}, None),
        "jetbrains-mono": ("jb/fonts/variable/JetBrainsMono[wght].ttf", "jb/fonts/variable/JetBrainsMono-Italic[wght].ttf", {}, {}, None),
        "monaspace-neon": ("mona/Variable Fonts/Monaspace Neon/Monaspace Neon Var.ttf", "mona/Variable Fonts/Monaspace Neon/Monaspace Neon Var.ttf",
                           {"wdth": 100, "slnt": 0}, {"wdth": 100, "slnt": -11}, "IFR Web 1"),
        "ibm-plex-mono": ("plex/fonts/complete/ttf/IBM Plex Mono Var-Roman.ttf", "plex/fonts/complete/ttf/IBM Plex Mono Var-Italic.ttf", {}, {}, "IFR Web 2"),
        "cascadia-code": ("cascadia/ttf/CascadiaCode.ttf", "cascadia/ttf/CascadiaCodeItalic.ttf", {}, {}, "IFR Web 3"),
        "fira-code": ("fira/variable_ttf/FiraCode-VF.ttf", None, {}, {}, None),
        "source-code-pro": ("scp/VF/SourceCodeVF-Upright.ttf", "scp/VF/SourceCodeVF-Italic.ttf", {}, {}, "IFR Web 4"),
        # D329 (#323). The other four Monaspace faces come from the archive Neon comes from. Every family below has its internal names
        # replaced: a subset is a Modified Version, and Intel One Mono (and others) reserve their names.
        "monaspace-argon": ("mona/Variable Fonts/Monaspace Argon/Monaspace Argon Var.ttf", "mona/Variable Fonts/Monaspace Argon/Monaspace Argon Var.ttf",
                            {"wdth": 100, "slnt": 0}, {"wdth": 100, "slnt": -11}, "IFR Web 5"),
        "monaspace-xenon": ("mona/Variable Fonts/Monaspace Xenon/Monaspace Xenon Var.ttf", "mona/Variable Fonts/Monaspace Xenon/Monaspace Xenon Var.ttf",
                            {"wdth": 100, "slnt": 0}, {"wdth": 100, "slnt": -11}, "IFR Web 6"),
        "monaspace-radon": ("mona/Variable Fonts/Monaspace Radon/Monaspace Radon Var.ttf", "mona/Variable Fonts/Monaspace Radon/Monaspace Radon Var.ttf",
                            {"wdth": 100, "slnt": 0}, {"wdth": 100, "slnt": -11}, "IFR Web 7"),
        "monaspace-krypton": ("mona/Variable Fonts/Monaspace Krypton/Monaspace Krypton Var.ttf", "mona/Variable Fonts/Monaspace Krypton/Monaspace Krypton Var.ttf",
                              {"wdth": 100, "slnt": 0}, {"wdth": 100, "slnt": -11}, "IFR Web 8"),
        # Recursive Mono: the mono axis on, the linear (not casual) design; italic is the cursive slanted one.
        "recursive-mono": ("recursive/ArrowType-Recursive-1.085/Recursive_Desktop/Recursive_VF_1.085.ttf", "recursive/ArrowType-Recursive-1.085/Recursive_Desktop/Recursive_VF_1.085.ttf",
                           {"MONO": 1, "CASL": 0, "CRSV": 0.5, "slnt": 0}, {"MONO": 1, "CASL": 0, "CRSV": 1, "slnt": -15}, "IFR Web 11"),
        # Martian Mono's standard width (its default is the widest, 112.5).
        "martian-mono": ("martianvf/MartianMonoVF.ttf", None, {"wdth": 100}, {}, "IFR Web 12"),
        "inconsolata": ("inconsolata/Inconsolata-VF.ttf", None, {"wdth": 100}, {}, "IFR Web 16"),
        "lilex": ("lilex/variable/Lilex[wght].ttf", "lilex/variable/Lilex-Italic[wght].ttf", {}, {}, "IFR Web 18"),
    }
    for family, (roman, italic, roman_pins, italic_pins, rename) in families.items():
        if only is not None and family not in only:
            continue
        variable(root / roman, out / family / "roman.latin.woff2", roman_pins, rename)
        if italic:
            variable(root / italic, out / family / "italic.latin.woff2", italic_pins, rename)
    # Families that ship static weights only (regular and bold, upright and italic): the registry maps 400-600 to the regular face and 700 to
    # the bold one. id: (folder under the extracted archive, file stem, the faces it has, the internal name).
    statics = {
        "iosevka": ("iosevka", "Iosevka-{}", "IFR Web 9"),
        "victor-mono": ("victor/TTF", "VictorMono-{}", "IFR Web 10"),
        "intel-one-mono": ("intel/ttf", "IntelOneMono-{}", "IFR Web 13"),
        "fantasque-sans-mono": ("fantasque/TTF", "FantasqueSansMono-{}", "IFR Web 14"),
        "hack": ("hack/ttf", "Hack-{}", "IFR Web 15"),
        "0xproto": ("oxproto/fonts", "0xProto-{}", "IFR Web 17"),
    }
    # The styles each static family has: 0xProto ships no bold italic, so its bold italic is the browser's slant of the bold.
    faces = {"roman-400": "Regular", "roman-700": "Bold", "italic-400": "Italic", "italic-700": "BoldItalic"}
    for family, (folder, stem, rename) in statics.items():
        if only is not None and family not in only:
            continue
        for target, style in faces.items():
            source = root / folder / f"{stem.format(style)}.ttf"
            if source.exists():
                static(source, out / family / f"{target}.latin.woff2", rename)
    # Commit Mono ships two static weights only; the registry maps 400-600 to the regular
    # face and 700 to the bold face.
    base = root / "cm/CommitMono-1.143/ttfautohint"
    for weight in (400, 700) if only is None or "commit-mono" in only else ():
        static(base / f"CommitMono-{weight}-Regular.ttf", out / "commit-mono" / f"roman-{weight}.latin.woff2", None)
        static(base / f"CommitMono-{weight}-Italic.ttf", out / "commit-mono" / f"italic-{weight}.latin.woff2", None)


if __name__ == "__main__":
    main()
