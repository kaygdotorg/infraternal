#!/usr/bin/env python3
"""Run the real functional daemon oracle while refusing performance-counter access (#169)."""
import argparse
from pathlib import Path
import runpy
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))


def refuse_measurement(*_args, **_kwargs):
    raise AssertionError("functional host provisioning gate reached a performance counter")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    namespace = runpy.run_path(str(ROOT / "scripts/verify-agent.py"))
    oracle = namespace["run"]
    oracle.__globals__["rss"] = refuse_measurement
    oracle.__globals__["assert_process_idle"] = refuse_measurement
    state = Path(tempfile.gettempdir()) / f"fm-{uuid.uuid4().hex[:16]}"
    oracle(args.binary.resolve(), state, functional=True)
    print("1 pass, 0 fail: real functional oracle made no performance-counter calls")


if __name__ == "__main__":
    main()
