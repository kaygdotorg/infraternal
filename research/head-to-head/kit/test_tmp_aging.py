#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Machine diff ignores only /tmp entries that tmpfiles aged out before a case (#260, #514)."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parent / "lib/tmp_aging.py"
SPEC = importlib.util.spec_from_file_location("h2h_tmp_aging", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
tmp_aging = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tmp_aging)

# Lines copied from `systemd-tmpfiles --cat-config` on a Debian 13 build VM.
CONFIG = """\
x /tmp/ssh-*
x /tmp/sshauth.*
x /tmp/systemd-private-%b-*
X /tmp/systemd-private-%b-*/tmp
R! /tmp/systemd-private-*
q /tmp 1777 root root 10d
x /tmp/tmux-*
D! /tmp/.X11-unix 1777 root root 10d
q /var/tmp 1777 root root 30d
"""
DAY = 86400
NOW = 2_000_000_000.0


class ParseRulesTest(unittest.TestCase):
    """The age and exemptions come from the /tmp rules, and nothing else."""

    def test_reads_tmp_age_and_exemptions_only(self) -> None:
        age, exempt = tmp_aging.parse_tmp_rules(CONFIG)
        self.assertEqual(age, 10 * DAY)
        self.assertIn("/tmp/ssh-*", exempt)
        self.assertIn("/tmp/systemd-private-*-*", exempt)
        self.assertIn("/tmp/tmux-*", exempt)
        self.assertFalse(any(pattern.startswith("/var/tmp") for pattern in exempt))

    def test_missing_tmp_rule_means_no_aging(self) -> None:
        age, _ = tmp_aging.parse_tmp_rules("q /var/tmp 1777 root root 30d\n")
        self.assertIsNone(age)

    def test_parse_age_units(self) -> None:
        self.assertEqual(tmp_aging.parse_age("10d"), 10 * DAY)
        self.assertEqual(tmp_aging.parse_age("30min"), 1800)
        self.assertEqual(tmp_aging.parse_age("2w"), 14 * DAY)
        self.assertEqual(tmp_aging.parse_age("1h30m"), 5400)
        self.assertEqual(tmp_aging.parse_age("~3d"), 3 * DAY)
        # Months and years are not handled: no age means nothing is ignored.
        self.assertIsNone(tmp_aging.parse_age("1M"))
        self.assertIsNone(tmp_aging.parse_age("-"))
        self.assertIsNone(tmp_aging.parse_age("10d junk"))


class RecordAndFilterTest(unittest.TestCase):
    """An aged removal is ignored; a young removal, an addition or an exempt name is not."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(prefix="h2h-tmp-aging-")
        self.root = Path(self._dir.name)
        self.addCleanup(self._dir.cleanup)

    def make(self, name: str, age_days: float) -> None:
        """Create /tmp entry `name` whose timestamps are `age_days` before NOW."""
        path = self.root / name
        path.mkdir()
        (path / "inner").write_text("x")
        stamp = NOW - age_days * DAY
        for target in (path / "inner", path):
            os.utime(target, (stamp, stamp))

    def record(self) -> dict:
        return tmp_aging.build_record(self.root, CONFIG, NOW)

    def test_aged_entry_removal_is_ignored(self) -> None:
        self.make("old-scratch", 20)
        kept, ignored = tmp_aging.filter_diff(
            self.record(), ["--- a\n", "+++ b\n", "@@ -1 +0,0 @@\n", "-/tmp/old-scratch d\n"]
        )
        self.assertEqual(ignored, ["old-scratch"])
        self.assertEqual(kept, [], "a diff with only ignored removals must read as empty")

    def test_young_entry_removal_is_kept(self) -> None:
        self.make("fresh", 2)
        kept, ignored = tmp_aging.filter_diff(self.record(), ["-/tmp/fresh d\n"])
        self.assertEqual(ignored, [])
        self.assertEqual(kept, ["-/tmp/fresh d\n"])

    def test_addition_is_kept_even_when_an_old_name_exists(self) -> None:
        self.make("old-scratch", 20)
        diff = ["-/tmp/old-scratch d\n", "+/tmp/new-leftover f\n"]
        kept, ignored = tmp_aging.filter_diff(self.record(), diff)
        self.assertEqual(ignored, ["old-scratch"])
        self.assertEqual(kept, ["+/tmp/new-leftover f\n"])

    def test_exempt_name_is_kept(self) -> None:
        self.make("systemd-private-abc123-svc", 20)
        self.make("ssh-XYZ", 20)
        kept, ignored = tmp_aging.filter_diff(
            self.record(), ["-/tmp/systemd-private-abc123-svc d\n", "-/tmp/ssh-XYZ d\n"]
        )
        self.assertEqual(ignored, [])
        self.assertEqual(len(kept), 2)

    def test_directory_with_fresh_content_is_not_aged(self) -> None:
        self.make("busy", 20)
        stamp = NOW - 1 * DAY
        os.utime(self.root / "busy" / "inner", (stamp, stamp))
        self.assertFalse(self.record()["entries"]["busy"]["aged"])

    def test_missing_record_ignores_nothing(self) -> None:
        self.make("old-scratch", 20)
        diff = ["-/tmp/old-scratch d\n"]
        kept, ignored = tmp_aging.filter_diff(None, diff)
        self.assertEqual((kept, ignored), (diff, []))

    def test_record_without_age_ignores_nothing(self) -> None:
        self.make("old-scratch", 20)
        record = tmp_aging.build_record(self.root, "", NOW)
        diff = ["-/tmp/old-scratch d\n"]
        self.assertEqual(tmp_aging.filter_diff(record, diff), (diff, []))

    def test_nested_removal_lines_are_not_top_level(self) -> None:
        self.make("old-scratch", 20)
        diff = ["-/tmp/old-scratch/inner f\n"]
        kept, ignored = tmp_aging.filter_diff(self.record(), diff)
        self.assertEqual((kept, ignored), (diff, []))


if __name__ == "__main__":
    unittest.main()
