#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check peer-count fixtures keep the one active traffic peer configured."""

from __future__ import annotations

import argparse
import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parent / "lib/peer_scale.py"
SPEC = importlib.util.spec_from_file_location("h2h_peer_scale", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
peer_scale = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(peer_scale)


class PeerScaleTest(unittest.TestCase):
    """Protect active-peer preservation in the matched kernel memory sample."""

    def test_kernel_config_keeps_active_peer_and_adds_requested_inert_peers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-peer-scale-") as temporary:
            output = Path(temporary) / "peers.conf"
            peer_scale.write_kernel_config(argparse.Namespace(
                count=2,
                start=1,
                output=str(output),
                active_public="ab" * 32,
                active_ip="10.66.0.2/32",
                active_endpoint="10.220.0.2:51821",
            ))
            content = output.read_text()
        self.assertEqual(content.count("[Peer]"), 3)
        self.assertIn("PublicKey = " + peer_scale.base64.b64encode(bytes.fromhex("ab" * 32)).decode(), content)
        self.assertIn("AllowedIPs = 10.66.0.2/32", content)
        self.assertIn("Endpoint = 10.220.0.2:51821", content)
        self.assertIn("AllowedIPs = 100.64.0.1/32", content)
        self.assertIn("AllowedIPs = 100.64.0.2/32", content)

    def test_kernel_config_preserves_interface_key_and_listen_port(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-peer-scale-interface-") as temporary:
            directory = Path(temporary)
            private_key = bytes(range(32))
            private_key_path = directory / "interface.private"
            private_key_path.write_text(
                peer_scale.base64.b64encode(private_key).decode("ascii") + "\n",
                encoding="ascii",
            )
            output = directory / "peers.conf"
            peer_scale.write_kernel_config(argparse.Namespace(
                count=1,
                start=1,
                output=str(output),
                active_public="ab" * 32,
                active_ip="10.66.0.2/32",
                active_endpoint="10.220.0.2:51821",
                interface_private_key_file=str(private_key_path),
                listen_port=51820,
            ))
            content = output.read_text(encoding="ascii")
            output_mode = output.stat().st_mode & 0o777
        self.assertIn(
            "PrivateKey = " + peer_scale.base64.b64encode(private_key).decode("ascii"),
            content,
        )
        self.assertIn("ListenPort = 51820", content)
        self.assertEqual(output_mode, 0o600)

    def test_partial_active_peer_arguments_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-peer-scale-invalid-") as temporary:
            output = Path(temporary) / "peers.conf"
            with self.assertRaises(ValueError):
                peer_scale.write_kernel_config(argparse.Namespace(
                    count=1,
                    start=1,
                    output=str(output),
                    active_public="ab" * 32,
                    active_ip=None,
                    active_endpoint=None,
                ))
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
