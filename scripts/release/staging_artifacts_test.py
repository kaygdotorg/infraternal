#!/usr/bin/env python3
"""Validate staging packaging against the real canonical signature and checksum verifier (#188 D1)."""
import hashlib
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

    def test_signer_format_is_admitted_and_wrong_key_tampering_and_traversal_are_refused(self):
        """Deploy admission reads exactly the signer Worker's SHA256SUMS format (#211 S1)."""
        scratch = Path(os.environ.get("INFRATERNAL_RELEASE_TEST_SCRATCH",
                       str(Path.home() / ".cache/codex-scratch/deploy-pipeline/tests")))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            trusts = []
            for name in ("key", "other"):
                key = root / name
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                public = key.with_suffix(".pub").read_text().split()
                trust = root / (name + ".trust")
                trust.write_text('release@infraternal.com namespaces="infraternal-release" ' + public[0] + " " + public[1] + " fixture\n")
                trusts.append(trust)
            trust, other = trusts
            image = root / "image"
            image.write_bytes(b"\x7fELFfixture-image\n")
            directory = root / "release"
            proof.bundle(directory, image, root / "key", "edge-20261114T000001Z")

            def resign(lines):
                (directory / "SHA256SUMS").write_text("".join(lines))
                (directory / "SHA256SUMS.sig").unlink()
                subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(root / "key"), "-n", "infraternal-release",
                                str(directory / "SHA256SUMS")], check=True, capture_output=True)

            # Real releases also sign nested license notices and other artifacts.
            signed = (directory / "SHA256SUMS").read_text().splitlines(keepends=True)
            notice = hashlib.sha256(b"notice").hexdigest() + "  licenses/libghostty-vt/README.md\n"
            resign(sorted(signed + [notice]))
            verify_signed(directory, trust, directory / "infraternal", complete=True)
            with self.assertRaises(subprocess.CalledProcessError):
                verify_signed(directory, other, directory / "infraternal", complete=True)
            for bad in ("licenses/../VERSION", "/etc/passwd", "licenses//README.md"):
                resign(sorted(signed + [hashlib.sha256(b"x").hexdigest() + "  " + bad + "\n"]))
                with self.assertRaisesRegex(ValueError, "invalid signed artifact list"):
                    verify_signed(directory, trust, directory / "infraternal", complete=True)
            resign([line for line in signed if not line.endswith("  infraternal-aarch64-musl\n")])
            with self.assertRaisesRegex(ValueError, "incomplete signed bundle"):
                verify_signed(directory, trust, directory / "infraternal", complete=True)
            resign(signed)
            (directory / "infraternal-aarch64-musl").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "signed artifact mismatch"):
                verify_signed(directory, trust, directory / "infraternal", complete=True)
            (directory / "SHA256SUMS.sig").unlink()
            with self.assertRaises(OSError):
                verify_signed(directory, trust, directory / "infraternal", complete=True)

    def test_signed_list_parser_is_as_strict_as_the_rust_verifier(self):
        """`signed_entries` refuses what `release_verify.rs` refuses (J685 P3-1)."""
        from deploy_remote import signed_entries
        line = hashlib.sha256(b"v").hexdigest() + "  VERSION"
        other = hashlib.sha256(b"x").hexdigest() + "  infraternal-x86_64-musl"
        self.assertEqual(set(signed_entries(line + "\n" + other + "\n")), {"VERSION", "infraternal-x86_64-musl"})
        # Rust's str::lines drops one carriage return before each newline (J685 P3-4).
        self.assertEqual(set(signed_entries(line + "\r\n" + other + "\r\n")), {"VERSION", "infraternal-x86_64-musl"})
        for separator in ("\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)), self.assertRaises(ValueError):
                signed_entries(line + separator + other + "\n")
        for text in ("", line, line + "\n" + other, line + "\n\n" + other + "\n", line + "\n" + line + "\n",
                     line.upper() + "\n", line + " \n", "x" * 65537 + "\n"):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                signed_entries(text)


if __name__ == "__main__":
    unittest.main()
