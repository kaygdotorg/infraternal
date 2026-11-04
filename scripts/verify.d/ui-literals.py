#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""`verify quick` row "ui literals": a change must not ADD raw style literals that a shared token already covers (#345).

Why. The interface is drawn in rem so the whole UI follows the UI size setting (packages/ui/src/ui-scale.ts), and its type,
corner radii and easing come from shared tokens (docs/design/TASTE.md section 2, docs/design/UI-CONSISTENCY-AUDIT.md). A pixel
font size ignores the UI size; a pixel radius drifts from the radius scale; a pasted easing curve forks the one in `--ease-out`.

What it checks. For every stylesheet and TypeScript file changed since the merge base, it counts three kinds of literal in the new
version and in the old one, and fails when the total of any kind went UP:
  font-size-px   `font-size: 13px` (a font size in pixels)
  radius-px      `border-radius: 6px` (a corner radius over 2 px in pixels; hairline shapes of 1-2 px are exempt, and so are 999px and 50%)
  ease-curve     `cubic-bezier(0.23, 1, 0.32, 1)` written out (use `var(--ease-out)`; the token definitions themselves are exempt)
It compares against the merge base, not against a stored number: no baseline file to conflict between branches, nothing to
update when someone removes a literal, and old literals are not this change's to fix.

Opting out. A literal that a decision or a TASTE row requires (a 16 px field so iOS does not zoom, D174's text scale) stays, and says
so: put `ui-literal: <D-number or TASTE row>` in a comment on the same line or the line above. The comment is the documentation.

Usage: ui-literals.py <base-ref>   (run from anywhere inside the repository; exits 1 and lists the added literals on failure)
"""
import re
import subprocess
import sys

RULES = {
    "font-size-px": re.compile(r"(?<![\w-])font-size\s*:\s*\d+(?:\.\d+)?px"),
    "radius-px": re.compile(r"(?<![\w-])border-radius\s*:\s*(?:[3-9]|\d{2,})(?:\.\d+)?px(?!\d)"),
    "ease-curve": re.compile(r"cubic-bezier\(\s*0\.23\s*,\s*1\s*,\s*0\.32\s*,\s*1\s*\)"),
}
# The token definitions are the one place the curve is written out.
DEFINITION = re.compile(r"--ease[\w-]*\s*:")
OPT_OUT = "ui-literal:"
ROOTS = ("apps/tracer/", "packages/ui/")
SUFFIXES = (".css", ".ts")
SKIP_PARTS = ("/node_modules/", "/test/", ".test.ts", ".spec.ts", "/vendor/", "/fonts/")


def git(*args: str) -> str:
    return subprocess.run(("git", *args), check=True, capture_output=True, text=True).stdout


def literals(text: str) -> dict[str, list[str]]:
    """Every counted literal in `text`, by rule, each as the offending line (skipping opted-out ones)."""
    found: dict[str, list[str]] = {name: [] for name in RULES}
    lines = text.splitlines()
    for number, line in enumerate(lines):
        if OPT_OUT in line or (number > 0 and OPT_OUT in lines[number - 1]):
            continue
        for name, pattern in RULES.items():
            if name == "ease-curve" and DEFINITION.search(line):
                continue
            found[name].extend([line.strip()[:110]] * len(pattern.findall(line)))
    return found


def show(ref: str, path: str) -> str:
    try:
        return git("show", f"{ref}:{path}")
    except subprocess.CalledProcessError:
        return ""  # the file is new on this side


def main() -> int:
    base = sys.argv[1]
    merge_base = git("merge-base", "HEAD", base).strip()
    changed = set(git("diff", "--name-only", merge_base).splitlines())
    changed |= set(git("ls-files", "--others", "--exclude-standard").splitlines())
    added: dict[str, list[str]] = {name: [] for name in RULES}
    totals = {name: 0 for name in RULES}
    for path in sorted(changed):
        if not path.startswith(ROOTS) or not path.endswith(SUFFIXES) or any(part in "/" + path for part in SKIP_PARTS):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                now = handle.read()
        except FileNotFoundError:
            now = ""  # deleted
        new, old = literals(now), literals(show(merge_base, path))
        for name in RULES:
            delta = len(new[name]) - len(old[name])
            totals[name] += delta
            if delta > 0:
                added[name].extend(f"{path}: {line}" for line in new[name][-delta:])
    bad = [name for name, delta in totals.items() if delta > 0]
    print("ui literals added vs merge base: " + ", ".join(f"{name} {totals[name]:+d}" for name in RULES))
    for name in bad:
        print(f"\n{name}: this change adds {totals[name]} (use the token, or opt out with `{OPT_OUT} <decision>`):")
        for line in added[name]:
            print(f"  {line}")
    return 1 if bad else 0


sys.exit(main())
