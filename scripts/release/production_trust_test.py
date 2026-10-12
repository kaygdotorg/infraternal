#!/usr/bin/env python3
"""Exercise the shipped-byte production trust gate against plain and marked images (#188 D1)."""
import importlib.util
from pathlib import Path
import tempfile
import os
import unittest

spec = importlib.util.spec_from_file_location("production_trust", Path(__file__).with_name("check-production-trust.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ProductionTrustTests(unittest.TestCase):
    def test_marker_survives_binary_padding_and_is_refused(self):
        scratch = Path(os.environ.get("INFRATERNAL_RELEASE_TEST_SCRATCH",
                       str(Path.home() / ".cache/codex-scratch/deploy-pipeline/tests")))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as root:
            binary = Path(root) / "image"
            binary.write_bytes(b"\x7fELF\0production-authority\xff")
            gate.check(binary)
            binary.write_bytes(b"\x7fELF\0infraternal-staging-trust-v1\xff")
            with self.assertRaises(ValueError):
                gate.check(binary)


if __name__ == "__main__":
    unittest.main()
