#!/usr/bin/env python3
"""Tests for scripts/verify.d/ios-dependency-guard.py (#580, T3): it must fail on a planted forbidden crate."""

import importlib.util
import unittest
from pathlib import Path

_PATH = Path(__file__).resolve().parent / "verify.d" / "ios-dependency-guard.py"
_SPEC = importlib.util.spec_from_file_location("ios_dependency_guard", _PATH)
guard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guard)

CLEAN = """\
infraternal-tunnel-ffi v0.1.0 (/x)
ring v0.17.14
ring feature "default"
tokio v1.52.0
tokio feature "rt"
tokio feature "net"
rustls v0.23.46
"""


class Guard(unittest.TestCase):
    """The guard passes a clean tree and names each planted offender."""

    def test_clean_tree_passes(self):
        """The proposed extension set is clean."""
        self.assertEqual(guard.offenders(CLEAN), [])

    def test_planted_openssl_fails(self):
        """A planted openssl dependency is reported by name."""
        self.assertEqual(guard.offenders(CLEAN + "openssl-sys v0.9.115\n"), ["openssl-sys"])

    def test_every_forbidden_package(self):
        """sqlx, libsqlite3-sys, aws-lc and openssl wrappers are all refused."""
        tree = "sqlx-sqlite v0.8.6\nlibsqlite3-sys v0.30.1\naws-lc-rs v1.16.2\naws-lc-sys v0.4.0\ntokio-openssl v0.6.5\n"
        self.assertEqual(guard.offenders(tree),
                         ["aws-lc-rs", "aws-lc-sys", "libsqlite3-sys", "sqlx-sqlite", "tokio-openssl"])

    def test_multi_thread_runtime_fails(self):
        """tokio's rt-multi-thread feature is refused; other tokio features are not."""
        self.assertEqual(guard.offenders(CLEAN + 'tokio feature "rt-multi-thread"\n'), ["tokio/rt-multi-thread"])

    def test_similar_names_are_not_offenders(self):
        """A crate whose name merely ends in a forbidden word, or a feature of that name, is fine."""
        self.assertEqual(guard.offenders("my-sqlx v1.0.0\nring feature \"sqlx\"\n"), [])


if __name__ == "__main__":
    unittest.main()
