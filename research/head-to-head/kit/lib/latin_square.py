#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Print Williams Latin-square orders for cross-engine holds (#260, J638).

Each hold (`perf-all.sh --mixed`) runs every engine once. Across the holds,
every engine takes every position equally often and directly follows every
other engine equally often (first-order carryover balance), so position effects
and slow drift cancel in the pooled within-hold ratios. With an even number of
engines that takes n holds; with an odd number, 2n (the square and its mirror).

Usage: latin_square.py ENGINE...   (one comma-separated order per line)
"""

from __future__ import annotations

import sys


def williams(items: list[str]) -> list[list[str]]:
    """Return the Williams design over `items`, one order per hold."""
    size = len(items)
    if size < 2:
        raise ValueError("a square needs at least two engines")
    # First row 0, 1, n-1, 2, n-2, ...; each later row adds one, modulo n.
    first = [0]
    low, high = 1, size - 1
    while len(first) < size:
        first.append(low)
        low += 1
        if len(first) < size:
            first.append(high)
            high -= 1
    orders = [[items[(index + shift) % size] for index in first] for shift in range(size)]
    if size % 2:
        orders += [list(reversed(order)) for order in orders]
    return orders


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    for order in williams(sys.argv[1:]):
        print(",".join(order))
    return 0


if __name__ == "__main__":
    sys.exit(main())
