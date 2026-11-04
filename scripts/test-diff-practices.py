#!/usr/bin/env python3
"""Exercise diff checks with body edits, lexical decoys and merge-base selection."""
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import unittest

SPEC = importlib.util.spec_from_file_location('practices', Path(__file__).parent / 'verify.d/diff-practices.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


class DiffPractices(unittest.TestCase):
    """Keep the cheap gate focused on changed items rather than legacy debt."""

    def test_deleted_item_leaves_neighbour_untouched(self):
        """Removing a whole function does not change the next function's body."""
        old = '//! Module.\nfn removed() {}\nfn untouched() {}\n'
        new = old.replace('fn removed() {}\n', '')
        self.assertFalse(p.check_docs('a.rs', old, new, 'rust'))

    def test_body_edit_and_legacy(self):
        """Changing a private function body requires docs; untouched neighbours do not."""
        old = '//! Module.\nfn stale() { old(); }\nfn changed() { old(); }\n'
        new = old.replace('fn changed() { old(); }', 'fn changed() { new(); }')
        self.assertEqual(len(p.check_docs('a.rs', old, new, 'rust')), 1)
        self.assertIn('changed needs', p.check_docs('a.rs', old, new, 'rust')[0])
        self.assertFalse(p.check_docs('a.rs', old, new.replace('fn changed', '/// Explain the operation.\nfn changed'), 'rust'))

    def test_deletion_is_a_change(self):
        """Deleting a body statement still changes its enclosing function."""
        old = '//! Module.\nfn work() {\n    first();\n    second();\n}\n'
        self.assertTrue(p.check_docs('a.rs', old, old.replace('    second();\n', ''), 'rust'))

    def test_attributes_and_strings(self):
        """Docs cross attributes; string contents cannot invent functions."""
        src = '//! Module.\n/// Read the constant.\n#[inline]\npub fn read() { let s = r#"fn decoy() {}"#; }\n'
        self.assertFalse(p.check_docs('a.rs', '', src, 'rust'))
        old = src.replace('#[inline]', '#[allow(clippy::too_many_lines)]')
        new = old.replace('#[allow(clippy::too_many_lines)]\n', '')
        self.assertFalse(p.check_docs('a.rs', old.replace('/// Read the constant.\n', ''), new.replace('/// Read the constant.\n', ''), 'rust'))

    def test_modules_and_nested_types(self):
        """New source files and inline modules need their own documentation."""
        self.assertTrue(p.check_docs('a.rs', '', '/// Work.\nfn work() {}\n', 'rust'))
        src = '//! Module.\nmod inner {\n//! Inner module.\n/// A value.\npub const VALUE: u8 = 1;\n}\n'
        self.assertFalse(p.check_docs('a.rs', '', src, 'rust'))

    def test_typescript_body(self):
        """Exported functions need docs when only their return value changes."""
        old = '/** @module Helpers. */\nexport function value() { return 1; }\n'
        self.assertTrue(p.check_docs('a.ts', old, old.replace('return 1', 'return 2'), 'ts'))
        new = old.replace('export function', '/** Read the value. */\nexport function')
        self.assertFalse(p.check_docs('a.ts', '', new, 'ts'))

    def test_inline_shape_attribute_cannot_hide_code(self):
        """An inline lint exception must not conceal an edited body."""
        old = '//! Module.\n#[allow(clippy::too_many_lines)] fn work() { old(); }\n'
        new = old.replace('old();', 'new();')
        self.assertTrue(p.check_docs('a.rs', old, new, 'rust'))

    def test_merge_base_and_staged_body(self):
        """The command checks staged and unstaged work against the real merge base."""
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                """Operate only on this throwaway repository."""
                return subprocess.check_output(['git', '-C', directory, *args], stderr=subprocess.DEVNULL)
            git('init', '-q')
            git('config', 'user.email', 'test@example.invalid')
            git('config', 'user.name', 'test')
            file = Path(directory) / 'file.rs'
            file.write_text('//! Module.\nfn work() { old(); }\n')
            git('add', 'file.rs')
            git('commit', '-qm', 'base')
            git('branch', 'base')
            file.write_text('//! Module.\nfn work() { new(); }\n')
            git('add', 'file.rs')
            command = ['python3', str(Path(p.__file__).resolve()), 'docs', 'base']
            result = subprocess.run(command, cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('work needs', result.stdout)
            file.write_text('//! Module.\n/// Perform work.\nfn work() { new(); }\n')
            self.assertEqual(subprocess.run(command, cwd=directory, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
