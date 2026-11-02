"""Checks the bounded release-time Traefik manifest builder without network access."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

import traefik_component


def archive(entries: list[tuple[str, bytes, str]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        for name, payload, kind in entries:
            member = tarfile.TarInfo(name)
            if kind == "file":
                member.type = tarfile.REGTYPE
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "../outside"
                bundle.addfile(member)
            else:
                raise AssertionError(f"unknown fixture entry kind: {kind}")
    return output.getvalue()


class ComponentManifestTests(unittest.TestCase):
    def test_bundle_binds_upstream_archive_to_the_infraternal_release_identity(self) -> None:
        payload = archive(
            [
                ("traefik", b"signed executable", "file"),
                ("LICENSE.md", b"MIT License\n", "file"),
            ]
        )
        filename = "traefik_v3.7.17_linux_amd64.tar.gz"
        digest = hashlib.sha256(payload).hexdigest()
        checksum_text = f"{digest}  {filename}\n"
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = traefik_component.write_component_bundle(
                "0.1.0", "linux", "amd64", io.BytesIO(payload), checksum_text, Path(temporary)
            )

            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["release_version"], "0.1.0")
            self.assertEqual(manifest["archive_sha256"], digest)
            self.assertEqual(manifest["archive_size"], len(payload))
            self.assertEqual(manifest["executable_sha256"], hashlib.sha256(b"signed executable").hexdigest())
            self.assertEqual(manifest["license"], "MIT")
            self.assertEqual(
                manifest["mirror_path"],
                "components/0.1.0/proxy/linux/amd64/traefik_v3.7.17_linux_amd64.tar.gz",
            )
            self.assertEqual(
                (Path(temporary) / manifest["mirror_path"]).read_bytes(), payload
            )

    def test_checksums_select_the_exact_upstream_asset_and_reject_tampering(self) -> None:
        payload = archive([("traefik", b"executable", "file")])
        filename = "traefik_v3.7.17_linux_amd64.tar.gz"
        digest = hashlib.sha256(payload).hexdigest()
        sums = traefik_component.parse_checksums(f"{digest}  {filename}\n")

        self.assertEqual(traefik_component.verify_checksum(io.BytesIO(payload), sums, filename), (digest, len(payload)))
        with self.assertRaises(ValueError):
            traefik_component.verify_checksum(io.BytesIO(payload + b"tamper"), sums, filename)

    def test_archive_inspection_accepts_the_official_allowlisted_members(self) -> None:
        payload = archive(
            [
                ("traefik", b"official executable", "file"),
                ("LICENSE.md", b"MIT License\n", "file"),
                ("CHANGELOG.md", b"release notes", "file"),
            ]
        )
        inspected = traefik_component.inspect_archive(io.BytesIO(payload))
        self.assertEqual(
            inspected["executable_sha256"],
            hashlib.sha256(b"official executable").hexdigest(),
        )

    def test_archive_inspection_rejects_unallowlisted_regular_members(self) -> None:
        payload = archive(
            [
                ("traefik", b"official executable", "file"),
                ("LICENSE.md", b"MIT License\n", "file"),
                ("README.md", b"ignored metadata", "file"),
            ]
        )
        with self.assertRaises(ValueError):
            traefik_component.inspect_archive(io.BytesIO(payload))

    def test_archive_inspection_rejects_links_and_parent_traversal(self) -> None:
        for member_name, kind in [("traefik-link", "symlink"), ("../outside", "file")]:
            with self.subTest(member_name=member_name):
                payload = archive(
                    [
                        ("traefik", b"official executable", "file"),
                        (member_name, b"", kind),
                    ]
                )
                with self.assertRaises(ValueError):
                    traefik_component.inspect_archive(io.BytesIO(payload))

    def test_checksum_parser_rejects_duplicate_paths_and_non_sha256_rows(self) -> None:
        with self.assertRaises(ValueError):
            traefik_component.parse_checksums("a" * 64 + "  same.tar.gz\n" + "b" * 64 + "  same.tar.gz\n")
        with self.assertRaises(ValueError):
            traefik_component.parse_checksums("not-a-digest  traefik.tar.gz\n")


if __name__ == "__main__":
    unittest.main()
