#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Record executable and in-kernel artifact size for each matrix row."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any


def file_info(value: str | None) -> dict[str, Any] | None:
    """Return logical and allocated size plus digest for one existing file."""
    if not value:
        return None
    path = Path(value).resolve()
    if not path.is_file():
        return None
    stat = path.stat()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": str(path),
        "size_bytes": stat.st_size,
        "disk_bytes": stat.st_blocks * 512,
        "sha256": digest,
    }


def kernel_module() -> dict[str, Any]:
    """Describe WireGuard's separate module file, if the running kernel has one."""
    modinfo = shutil.which("modinfo")
    module_path = None
    if modinfo:
        try:
            result = subprocess.run(
                [modinfo, "-F", "filename", "wireguard"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if result.returncode == 0:
                module_path = result.stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            pass
    if module_path and module_path != "(builtin)":
        return {"kind": "module-file", "module": file_info(module_path)}
    image = Path(f"/boot/vmlinuz-{platform.release()}")
    return {
        "kind": "kernel-built-in" if module_path == "(builtin)" else "module-file-unresolved",
        "module_path": module_path,
        "running_kernel": platform.release(),
        "kernel_image": file_info(str(image)) if image.is_file() else None,
    }


def build(engine: str, binary: str | None, wg_tool: str | None) -> dict[str, Any]:
    engine_file = file_info(binary)
    tool_file = file_info(wg_tool)
    result: dict[str, Any] = {
        "schema_version": 1,
        "engine": engine,
        "engine_binary": engine_file,
        "engine_binary_size_bytes": engine_file["size_bytes"] if engine_file else None,
        "engine_binary_disk_bytes": engine_file["disk_bytes"] if engine_file else None,
        "wg_administration_tool": tool_file,
    }
    if engine == "kernel-plain":
        result["in_kernel_artifact"] = kernel_module()
        result["engine_binary_basis"] = "no separate userspace engine executable"
    else:
        result["engine_binary_basis"] = "userspace engine executable"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, choices=["kernel-plain", "wireguard-go", "gotatun"])
    parser.add_argument("--binary")
    parser.add_argument("--wg-tool")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    value = build(args.engine, args.binary, args.wg_tool)
    Path(args.output).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
