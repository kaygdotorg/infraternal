# SPDX-License-Identifier: AGPL-3.0-only
"""Tell apart /tmp entries that systemd-tmpfiles aged out from changes a case made (#260, #514).

The machine snapshot lists the top-level entries of /tmp. systemd-tmpfiles deletes
old /tmp entries on its own timer, so a case that runs for longer than the age rule
can see an entry vanish that nothing in the case touched. That removal is noise, not
a leftover. This module lets run.sh ignore exactly those removals and nothing else.

How it works, in two steps that run.sh performs around each case:

  record  (before the case) reads the effective tmpfiles rules with
          `systemd-tmpfiles --cat-config`, takes the age rule for /tmp and the `x`
          exemptions, and for every top-level entry of /tmp records its newest
          atime, mtime or ctime (directories include their contents, as tmpfiles does)
          and whether that is already older than the age rule.

  filter  (after the case) drops a `-` diff line only when the entry it names was
          recorded as already aged and is not exempt. Added entries, young removals,
          entries of any other kind, and every other diff line stay.

Fail-closed rules: no record, an unreadable record, an age we cannot parse, or no
/tmp age rule means nothing is ignored, so the diff is reported exactly as before.
An entry that was aged before the case and deleted during it is also ignored, which
is the one place a case's own deletion could hide. That trade-off is deliberate: a
case that removes an old /tmp entry it did not create is rare, and the snapshot
cannot tell the two apart without a per-process audit.

Usage:
  tmp_aging.py record            > tmp-before.json     (reads the live host)
  tmp_aging.py filter FILE.json RAW_DIFF > machine-diff.txt   (ignored list on stderr)
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

TMP_ROOT = "/tmp"
# Seconds per unit that tmpfiles accepts in an age field. Months and years are left
# out on purpose: an age we cannot parse is treated as "no age", which ignores nothing.
UNIT_SECONDS = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "d": 86400, "w": 604800}
# A top-level /tmp line in the snapshot diff is "/tmp/<name> <one-letter type>".
# Deeper paths never appear in that section, so a bare name is enough.
TOP_LEVEL_REMOVAL = re.compile(r"^-/tmp/([^/\s]+) [a-zA-Z]$")


def parse_age(text: str) -> int | None:
    """Return the age in seconds for a tmpfiles age field, or None if it is not one we handle.

    A leading `~` is stripped. Compound ages such as `1h30m` add up; anything with an
    unknown unit, or with stray text between the numbers and units, returns None.
    """
    body = text.lstrip("~")
    if not body or body == "-":
        return None
    total = 0
    consumed = 0
    for match in re.finditer(r"(\d+)([A-Za-z]+)", body):
        number, unit = match.group(1), match.group(2)
        if unit not in UNIT_SECONDS:
            return None
        total += int(number) * UNIT_SECONDS[unit]
        consumed += len(match.group(0))
    if consumed != len(body) or total == 0:
        return None
    return total


def parse_tmp_rules(config: str) -> tuple[int | None, list[str]]:
    """Read the /tmp age and the `x` exemptions from `systemd-tmpfiles --cat-config` text.

    Returns (age seconds or None, exempt glob patterns). The last line that gives /tmp an
    age wins, which matches how later tmpfiles.d definitions override earlier ones. A
    `%b` specifier (the boot-random part of systemd-private names) is turned into `*` so
    the exemption still matches. Only the exact `/tmp` path sets the age; the `/var/tmp`
    rule is for another tree and is not read here.
    """
    age: int | None = None
    exempt: list[str] = []
    for raw in config.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        kind = fields[0].rstrip("!-+=~")
        path = fields[1]
        if kind == "x" and path.startswith(TMP_ROOT + "/"):
            exempt.append(path.replace("%b", "*"))
        elif kind in {"d", "D", "q", "Q", "e"} and path == TMP_ROOT and len(fields) > 5:
            parsed = parse_age(fields[5])
            if parsed is not None:
                age = parsed
    return age, exempt


def newest_timestamp(path: Path) -> float:
    """Return the newest atime, mtime or ctime of `path`, looking inside directories too.

    tmpfiles ages a directory by its newest content, so a busy directory with an old
    name is not aged. Symbolic links are not followed, so a link to another tree cannot
    make a /tmp entry look young (or old) because of that tree.
    """
    newest = 0.0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            status = os.lstat(current)
        except OSError:
            continue
        newest = max(newest, status.st_atime, status.st_mtime, status.st_ctime)
        if os.path.isdir(current) and not os.path.islink(current):
            try:
                stack.extend(Path(current, name) for name in os.listdir(current))
            except OSError:
                continue
    return newest


def build_record(tmp_root: Path, config: str, now: float) -> dict:
    """Build the record that `filter` reads: the rule plus, per top-level /tmp entry, its age state.

    `now` is passed in (rather than read here) so tests can state exactly which entries
    count as aged. Each entry is stored by its name only, with `aged` true when its newest
    timestamp is older than the rule at snapshot time.
    """
    age, exempt = parse_tmp_rules(config)
    entries: dict[str, dict] = {}
    if age is not None and tmp_root.is_dir():
        for child in sorted(tmp_root.iterdir()):
            newest = newest_timestamp(child)
            # Patterns name real /tmp paths, so match the name under /tmp, not under tmp_root.
            exempted = any(fnmatch.fnmatchcase(f"{TMP_ROOT}/{child.name}", pattern) for pattern in exempt)
            entries[child.name] = {
                "aged": (now - newest) > age and not exempted,
                "newest": newest,
            }
    return {"version": 1, "age_seconds": age, "exempt": exempt, "entries": entries}


def filter_diff(record: dict | None, diff_lines: Iterable[str]) -> tuple[list[str], list[str]]:
    """Return (kept diff lines, names of ignored aged /tmp removals).

    A line is ignored only when it is a `-` removal of a top-level /tmp entry that the
    record marks as aged. A missing record ignores nothing. If every changed line is
    ignored, the kept list has no `+` or `-` lines, so the caller can call the diff empty.
    """
    lines = list(diff_lines)
    if record is None or record.get("version") != 1 or record.get("age_seconds") is None:
        return lines, []
    entries = record.get("entries", {})
    kept: list[str] = []
    ignored: list[str] = []
    for line in lines:
        match = TOP_LEVEL_REMOVAL.match(line.rstrip("\n")) if line.startswith("-") else None
        if match and not line.startswith("---"):
            name = match.group(1)
            entry = entries.get(name)
            if entry and entry.get("aged"):
                ignored.append(name)
                continue
        kept.append(line)
    if not any(line.startswith(("+", "-")) and not line.startswith(("+++", "---")) for line in kept):
        return [], ignored
    return kept, ignored


def record_command() -> int:
    """Print the record for the live host (run.sh's before-case step)."""
    try:
        config = subprocess.run(
            ["systemd-tmpfiles", "--cat-config"], capture_output=True, text=True, check=True, timeout=30
        ).stdout
    except (OSError, subprocess.SubprocessError):
        config = ""
    record = build_record(Path(TMP_ROOT), config, time.time())
    json.dump(record, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def filter_command(record_path: str, diff_path: str) -> int:
    """Print the diff with aged /tmp removals dropped; say what was ignored on stderr."""
    try:
        record = json.loads(Path(record_path).read_text())
    except (OSError, ValueError):
        record = None
    kept, ignored = filter_diff(record, Path(diff_path).read_text().splitlines(keepends=True))
    sys.stdout.write("".join(kept))
    if ignored:
        sys.stderr.write(
            f"ignored {len(ignored)} tmpfiles-aged /tmp removal(s): {' '.join(sorted(ignored))}\n"
        )
    return 0


def main(argv: list[str]) -> int:
    """Dispatch the `record` and `filter` subcommands; bad usage exits with status 2."""
    if argv[:1] == ["record"] and len(argv) == 1:
        return record_command()
    if argv[:1] == ["filter"] and len(argv) == 3:
        return filter_command(argv[1], argv[2])
    sys.stderr.write(__doc__ or "usage: tmp_aging.py record | filter RECORD DIFF\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
