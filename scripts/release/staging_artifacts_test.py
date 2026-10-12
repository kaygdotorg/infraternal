#!/usr/bin/env python3
"""Validate staging packaging against the real canonical signature and checksum verifier (#188 D1)."""
import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import os
import unittest

from deploy_remote import checksums, verify_signed

loader = importlib.machinery.SourceFileLoader("staging_proof", str(Path(__file__).with_name("staging-proof")))
spec = importlib.util.spec_from_loader(loader.name, loader)
proof = importlib.util.module_from_spec(spec)
loader.exec_module(proof)


class StagingArtifactsTests(unittest.TestCase):
    def test_distinct_images_and_version_are_authenticated_by_one_ephemeral_key(self):
        scratch = Path(os.environ.get("INFRATERNAL_RELEASE_TEST_SCRATCH",
                       str(Path.home() / ".cache/codex-scratch/deploy-pipeline/tests")))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            key = root / "key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            public = key.with_suffix(".pub").read_text().split()
            trust = root / "trust"
            trust.write_text('release@infraternal.com namespaces="infraternal-release" ' + public[0] + " " + public[1] + " fixture\n")
            image = root / "image"
            image.write_bytes(b"\x7fELFfixture-image\n")
            for name, suffix, stamp in (("A", b"", "01"), ("B", b"new-image", "02"), ("C", b"broken-image", "03")):
                directory = root / name
                proof.bundle(directory, image, key, "edge-20261012T0000" + stamp + "Z", suffix)
                checksums(directory)
                verify_signed(directory, trust, directory / "infraternal", complete=True)
            key.unlink()
            self.assertNotEqual((root / "A/infraternal").read_bytes(), (root / "B/infraternal").read_bytes())
            (root / "B/VERSION").write_text("edge-20261012T000004Z\n")
            with self.assertRaises(ValueError):
                verify_signed(root / "B", trust, root / "B/infraternal", complete=True)


if __name__ == "__main__":
    unittest.main()
