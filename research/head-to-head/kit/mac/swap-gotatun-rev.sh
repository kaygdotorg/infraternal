#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Point a throw-away copy of the checkout at a candidate GotaTun rev, and prove that nothing else
# moved (#260, J679, J733). Used by build-harness.sh; runs on any OS (no `sed -i`).
#
#   swap-gotatun-rev.sh <checkout-copy> <rev>
#
# 1. Finds the pinned dependency in the workspace manifest or the older plugin manifest,
#    replaces its revision, and checks that exactly that one line changed.
# 2. Lets cargo re-resolve Cargo.lock (`cargo metadata`; $CARGO overrides the binary, for tests).
# 3. Checks that the lock changed ONLY in the three packages from the pinned GotaTun fork.
#    Upstream extracted gotatun-crypto and gotatun-packet in 0.10.3. Their source must move with
#    gotatun; a same-named registry package or another repository is never exempt. Any other
#    added, removed or
#    changed package (a dependency drift that would make pin and candidate differ in more than
#    GotaTun) fails with exit 2 and names it. The caller then builds with `--locked` again.
set -euo pipefail
SRC=${1:?checkout copy}; REV=${2:?gotatun rev}
[[ $REV =~ ^[0-9a-f]{7,40}$ ]] || { echo "gotatun rev must be 7-40 hex digits: $REV" >&2; exit 2; }
TOML=$SRC/Cargo.toml
if [[ ! -f "$TOML" ]] || ! grep -q '^gotatun = .*rev = "' "$TOML"; then
  TOML=$SRC/crates/plugins/mesh/Cargo.toml
fi
sed -E "/^gotatun = /s/rev = \"[0-9a-f]+\"/rev = \"$REV\"/" "$TOML" > "$TOML.new"
changed=$(diff "$TOML" "$TOML.new" | grep -c '^>' || true)
[ "$changed" = 1 ] || { echo "expected exactly one changed line in $TOML, got $changed" >&2; rm -f "$TOML.new"; exit 2; }
grep -q "^gotatun = .*rev = \"$REV\"" "$TOML.new" || { echo "could not set the gotatun rev in $TOML" >&2; rm -f "$TOML.new"; exit 2; }
mv "$TOML.new" "$TOML"

cp "$SRC/Cargo.lock" "$SRC/Cargo.lock.orig"
(cd "$SRC" && ${CARGO:-cargo} metadata --format-version 1 > /dev/null)
if ! python3 -I - "$SRC/Cargo.lock.orig" "$SRC/Cargo.lock" "$REV" <<'EOF'
"""Allow only a coherent revision change of the existing fork's three packages."""
import sys

def entries(path):
    """Read Cargo's package blocks while retaining their bytes for unrelated-drift checks."""
    blocks = open(path).read().split("\n[[package]]\n")[1:]
    result = []
    for block in blocks:
        name = next(l.split('"')[1] for l in block.splitlines() if l.startswith("name = "))
        source = next((l.split('"')[1] for l in block.splitlines() if l.startswith("source = ")), "")
        result.append((name, source, block.split("\n\n")[0].strip()))
    return result

def main_source(entries):
    """Require one Git-sourced main crate so split crates inherit a specific source identity."""
    sources = [source for name, source, _ in entries if name == "gotatun"]
    if len(sources) != 1 or not sources[0].startswith("git+"):
        sys.exit("expected one Git-sourced gotatun entry before and after")
    return sources[0]

def packages(entries, fork_source):
    """Exclude only coherent fork components; preserve every other entry for byte comparison."""
    kept, seen = set(), set()
    for name, source, block in entries:
        if name in {"gotatun", "gotatun-crypto", "gotatun-packet"} and source == fork_source:
            if name in seen:
                sys.exit("duplicate fork package: " + name)
            seen.add(name)
        else:
            kept.add(block)
    return kept

old_entries, new_entries = entries(sys.argv[1]), entries(sys.argv[2])
old_source, new_source = main_source(old_entries), main_source(new_entries)
repository = old_source.split("?", 1)[0]
if not new_source.startswith(repository + "?rev=" + sys.argv[3] + "#"):
    sys.exit("the lock must resolve the requested revision from the existing fork repository")
if not new_source.split("#", 1)[1].startswith(sys.argv[3]):
    sys.exit("the resolved fork commit does not match the requested revision")
old, new = packages(old_entries, old_source), packages(new_entries, new_source)
bad = sorted({b.splitlines()[0] for b in old ^ new})
if bad:
    sys.exit("Cargo.lock changed outside gotatun: " + ", ".join(bad))
EOF
then
  echo "LOCK_DRIFT: the candidate is not a pure GotaTun swap" >&2; exit 2
fi
echo "swap ok: rev $REV, Cargo.lock changed only in the GotaTun fork packages"
