#!/usr/bin/env python3
"""Keep D351's workspace policy and local lint exceptions consistent.

D351 turned clippy's `too_many_lines` and `too_many_arguments` off. This check
fails if either comes back: in the workspace lint table, in a member's own
lint table, or as an `allow`/`expect` attribute on an item. It reads the
working tree, including new files that are not staged yet, so `verify quick`
catches an exception before it is committed.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXCEPTION = re.compile(r'#!?\[(?:allow|expect|cfg_attr)\([^\]]*clippy::too_many_(?:lines|arguments)')


def source_files(root, pattern):
    """Tracked and untracked (not ignored) files matching `pattern`, relative to `root`."""
    listed = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard', pattern],
                                     cwd=root).decode().split('\0')
    return sorted({path for path in listed if path and (root / path).is_file()})


def local_exceptions(root):
    """Paths of Rust files that still carry a retired shape-lint exception."""
    return [path for path in source_files(root, '*.rs')
            if not path.startswith(('vendor/', 'research/')) and EXCEPTION.search((root / path).read_text())]


class ShapeLints(unittest.TestCase):
    """Reject reintroduced shape limits and their redundant local exceptions."""

    def test_workspace_policy(self):
        """The two shape lints override the pedantic group for every package."""
        config = tomllib.loads((ROOT / 'Cargo.toml').read_text())
        for lint in ('too_many_lines', 'too_many_arguments'):
            self.assertEqual(config['workspace']['lints']['clippy'].get(lint), 'allow')

    def test_member_lint_tables(self):
        """A member with its own lint table cannot inherit the override, so it repeats it.

        research/ probes are throwaway experiments outside the product build.
        """
        for path in source_files(ROOT, '*Cargo.toml'):
            if path.startswith(('vendor/', 'research/')) or path == 'Cargo.toml':
                continue
            clippy = tomllib.loads((ROOT / path).read_text()).get('lints', {}).get('clippy')
            if not isinstance(clippy, dict) or 'pedantic' not in clippy:
                continue
            for lint in ('too_many_lines', 'too_many_arguments'):
                self.assertEqual(clippy.get(lint), 'allow', f'{path}: {lint}')

    def test_no_local_exceptions(self):
        """Individual items inherit the workspace choice without allow attributes."""
        self.assertEqual(local_exceptions(ROOT), [])

    def test_untracked_files_are_checked(self):
        """A new, unstaged file with an exception is found (review finding 79562)."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            (root / 'tracked.rs').write_text('fn ok() {}\n')
            subprocess.run(['git', 'add', 'tracked.rs'], cwd=root, check=True)
            (root / 'new.rs').write_text('#[allow(clippy::too_many_lines)]\nfn long() {}\n')
            (root / '.gitignore').write_text('ignored.rs\n')
            (root / 'ignored.rs').write_text('#[allow(clippy::too_many_arguments)]\nfn x() {}\n')
            self.assertEqual(local_exceptions(root), ['new.rs'])


if __name__ == '__main__':
    unittest.main()
