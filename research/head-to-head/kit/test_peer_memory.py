#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that kernel peer memory uses named slabs when available."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parent / "lib/peer_memory.py"
SPEC = importlib.util.spec_from_file_location("h2h_peer_memory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
peer_memory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(peer_memory)


class PeerMemoryTest(unittest.TestCase):
    """Keep generic slab growth distinguishable from WireGuard cache data."""

    def test_counts_only_wireguard_named_slab_caches(self) -> None:
        slabinfo = """slabinfo - version: 2.1
# name <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>
wg_peer 10 16 256 16 1
wireguard_peer 2 4 512 4 1
kmalloc-256 99 128 256 16 1
"""
        result = peer_memory.parse_slabinfo(slabinfo)
        self.assertEqual(result["named_cache_bytes"], 6144)
        self.assertEqual([cache["name"] for cache in result["caches"]], ["wg_peer", "wireguard_peer"])

    def test_no_named_cache_is_not_reported_as_zero_peer_memory(self) -> None:
        result = peer_memory.parse_slabinfo("# name active_objs num_objs objsize\nkmalloc-256 3 4 256\n")
        self.assertIsNone(result["named_cache_bytes"])
        self.assertEqual(result["caches"], [])

    def test_crypto_cache_is_not_mislabeled_as_peer_memory(self) -> None:
        result = peer_memory.parse_slabinfo("wg_crypt 10 16 256 16 1\n")
        self.assertIsNone(result["named_cache_bytes"])
        self.assertEqual(result["caches"], [])

    def test_meminfo_fallback_is_not_published_as_a_peer_slab_value(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-meminfo-fallback-") as temporary:
            root = Path(temporary)
            baseline = root / "baseline.json"
            process_memory = root / "process-memory.json"
            baseline.write_text(json.dumps({
                "slabinfo": {"named_cache_bytes": None},
                "meminfo": {"Slab": 102400},
            }), encoding="utf-8")
            process_memory.write_text(json.dumps({"rss_kb": 0}), encoding="utf-8")
            real_read_text = Path.read_text

            def read_text(path: Path, *args: object, **kwargs: object) -> str:
                if str(path) == "/proc/slabinfo":
                    return "# name active_objs num_objs objsize\nkmalloc-256 3 4 256\n"
                if str(path) == "/proc/meminfo":
                    return "Slab: 180 kB\n"
                return real_read_text(path, *args, **kwargs)

            args = Namespace(
                engine="kernel-plain", peers=100, baseline=baseline,
                process_memory=process_memory, raw_dir=None,
            )
            with patch.object(Path, "read_text", autospec=True, side_effect=read_text):
                result = peer_memory.snapshot(args)

        self.assertEqual(result["kernel_peer_memory_bytes"], 81920)
        self.assertEqual(result["system_wide_meminfo_slab_delta_bytes"], 81920)
        self.assertIn("system-wide /proc/meminfo", result["kernel_peer_memory_basis"])
        self.assertNotIn("kernel_peer_slab_bytes", result)

    def test_idle_and_loaded_snapshots_keep_separate_state_and_raw_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-peer-memory-state-") as temporary:
            root = Path(temporary)
            process_memory = root / "process-memory.json"
            raw_dir = root / "raw"
            process_memory.write_text(json.dumps({"rss_kb": 2048, "pss_kb": 1024}), encoding="utf-8")
            real_read_text = Path.read_text

            def read_text(path: Path, *args: object, **kwargs: object) -> str:
                if str(path) == "/proc/slabinfo":
                    return "# name active_objs num_objs objsize\nwg_peer 1 2 256\n"
                if str(path) == "/proc/meminfo":
                    return "Slab: 4 kB\n"
                return real_read_text(path, *args, **kwargs)

            snapshots = {}
            with patch.object(Path, "read_text", autospec=True, side_effect=read_text):
                for state in ("idle", "loaded"):
                    args = Namespace(
                        engine="gotatun", peers=100, baseline=None,
                        process_memory=process_memory, raw_dir=raw_dir, state=state,
                    )
                    snapshots[state] = peer_memory.snapshot(args)
                    self.assertTrue((raw_dir / f"slabinfo-100-{state}.txt").is_file())
                    self.assertTrue((raw_dir / f"meminfo-100-{state}.txt").is_file())

        self.assertEqual(snapshots["idle"]["measurement_state"], "idle")
        self.assertEqual(snapshots["loaded"]["measurement_state"], "loaded")


if __name__ == "__main__":
    unittest.main()
