#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Point a throw-away copy of the checkout at a candidate GotaTun rev, and prove that nothing else
# moved (#260, J679, J733). Used by build-harness.sh; runs on any OS (no `sed -i`).
#
#   swap-gotatun-rev.sh <checkout-copy> <rev>
#
# 1. Replaces `rev = "..."` on the one `gotatun = ` line of crates/plugins/mesh/Cargo.toml and
#    checks that exactly that one line changed.
# 2. Lets cargo re-resolve Cargo.lock (`cargo metadata`; $CARGO overrides the binary, for tests).
# 3. Checks that the lock changed ONLY in the `gotatun` package entry. Any other added, removed or
#    changed package (a dependency drift that would make pin and candidate differ in more than
#    GotaTun) fails with exit 2 and names it. The caller then builds with `--locked` again.
set -euo pipefail
SRC=${1:?checkout copy}; REV=${2:?gotatun rev}
[[ $REV =~ ^[0-9a-f]{7,40}$ ]] || { echo "gotatun rev must be 7-40 hex digits: $REV" >&2; exit 2; }
TOML=$SRC/crates/plugins/mesh/Cargo.toml
sed -E "/^gotatun = /s/rev = \"[0-9a-f]+\"/rev = \"$REV\"/" "$TOML" > "$TOML.new"
changed=$(diff "$TOML" "$TOML.new" | grep -c '^>' || true)
[ "$changed" = 1 ] || { echo "expected exactly one changed line in $TOML, got $changed" >&2; rm -f "$TOML.new"; exit 2; }
grep -q "^gotatun = .*rev = \"$REV\"" "$TOML.new" || { echo "could not set the gotatun rev in $TOML" >&2; rm -f "$TOML.new"; exit 2; }
mv "$TOML.new" "$TOML"

cp "$SRC/Cargo.lock" "$SRC/Cargo.lock.orig"
(cd "$SRC" && ${CARGO:-cargo} metadata --format-version 1 > /dev/null)
if ! python3 -I - "$SRC/Cargo.lock.orig" "$SRC/Cargo.lock" <<'EOF'
import sys

def packages(path):
    """Map each non-gotatun lock entry to itself; gotatun entries are the expected change."""
    blocks = open(path).read().split("\n[[package]]\n")[1:]
    kept, gotatun = set(), 0
    for block in blocks:
        name = next(l.split('"')[1] for l in block.splitlines() if l.startswith("name = "))
        if name == "gotatun":
            gotatun += 1
        else:
            kept.add(block.split("\n\n")[0].strip())
    return kept, gotatun

old, old_g = packages(sys.argv[1])
new, new_g = packages(sys.argv[2])
if old_g != 1 or new_g != 1:
    sys.exit(f"expected one gotatun entry before and after, got {old_g} and {new_g}")
bad = sorted({b.splitlines()[0] for b in old ^ new})
if bad:
    sys.exit("Cargo.lock changed outside gotatun: " + ", ".join(bad))
EOF
then
  echo "LOCK_DRIFT: the candidate is not a pure GotaTun swap" >&2; exit 2
fi
echo "swap ok: rev $REV, Cargo.lock changed only in gotatun"
