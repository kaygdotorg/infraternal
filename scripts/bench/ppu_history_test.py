"""Check residency attribution for an anonymous worker stack and spaced image path [#205].

SPDX-License-Identifier: AGPL-3.0-only
"""
from pathlib import Path
import unittest
from ppu_history import parse_mappings


class Residency(unittest.TestCase):
    def test_worker_stack_boundary_and_image_path_are_distinct(self):
        raw = """1000-2000 r-xp 00000000 00:01 1 /fixture with space
Pss: 4 kB
Rss: 4 kB
2000-3000 rw-p 00000000 00:00 0
Pss: 8 kB
Anonymous: 8 kB
3000-4000 rw-p 00000000 00:00 0
Pss: 12 kB
Anonymous: 12 kB
4000-5000 rw-p 00000000 00:00 0 [stack]
Pss: 16 kB
"""
        groups = parse_mappings(raw, Path('/fixture with space'), 0x3000)
        self.assertEqual(groups['image'], {'Pss_kib': 4, 'Rss_kib': 4})
        self.assertEqual(groups['anonymous'], {'Pss_kib': 8, 'Anonymous_kib': 8})
        self.assertEqual(groups['worker_stack'], {'Pss_kib': 12, 'Anonymous_kib': 12})
        self.assertEqual(groups['main_stack'], {'Pss_kib': 16})


if __name__ == '__main__':
    unittest.main()
