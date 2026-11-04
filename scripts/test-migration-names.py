#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the D347 guard and helper with isolated files, never repository migrations."""
import importlib.machinery
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

# Import this checkout's scripts, including when tests are launched from another directory.
ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    """Import an executable Python script without running its command-line entry point."""
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class MigrationNames(unittest.TestCase):
    """Catch legacy exemptions that admit new numbers and timestamp collisions."""

    def test_guard_rejects_new_numbers_and_duplicate_integer_versions(self):
        """Old names stay valid; new numbers, renamed old files and aliases fail."""
        guard = load("migration_names", ROOT / "scripts/verify.d/migration-names.py")
        legacy = guard.legacy_names()
        self.assertEqual(guard.check_names(legacy), [])
        for name in ("0049_new.sql", "0041_other.sql", "1_renamed.sql", "0001_renamed.sql"):
            with self.subTest(name=name):
                self.assertTrue(guard.check_names([name]))
        for names in (
            ["20261104153000_one.sql", "20261104153000_two.sql"],
            ["0001_auth.sql", "1_other.sql"],
        ):
            self.assertTrue(any("duplicate" in error for error in guard.check_names(names)))
        self.assertEqual(guard.check_names([*legacy, "20261104153000_new.sql"]), [])
        for name in ("20260230153000_bad.sql", "202611041530_bad.sql", "oops.sql"):
            self.assertTrue(guard.check_names([name]))

    def test_helper_uses_utc_and_refuses_collision_without_overwriting(self):
        """Two calls in one second must not silently create duplicate versions."""
        helper = load("new_migration", ROOT / "scripts/new-migration")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            now = datetime(2026, 11, 4, 21, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
            path = helper.create_migration(directory, "add_foo", now)
            self.assertEqual(path.name, "20261104153000_add_foo.sql")
            original = path.read_bytes()
            for name in ("add_foo", "different_name"):
                with self.assertRaises(FileExistsError):
                    helper.create_migration(directory, name, now)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(len(list(directory.iterdir())), 1)
            for name in ("../escape", "has spaces", "", "Uppercase"):
                with self.assertRaises(ValueError):
                    helper.create_migration(directory, name, now)


if __name__ == "__main__":
    unittest.main()
