#!/usr/bin/env python3
"""Check that shared owner processes are counted once in session RSS totals."""
from pathlib import Path
import runpy

root = Path(__file__).resolve().parent.parent
scale = runpy.run_path(str(root / "crates/infraternal-shim/tests/vt_scale.py"))
summarize = scale["summarize_rss"]

shared = summarize([41, 41, 41], {41: 100}, {41: 460})
assert shared == (1, 460, 360, 120.0), shared

separate = summarize([41, 42], {41: 100, 42: 250}, {41: 460, 42: 550})
assert separate == (2, 1010, 660, 330.0), separate

print("PASS: RSS totals deduplicate owner processes and divide growth by sessions")
