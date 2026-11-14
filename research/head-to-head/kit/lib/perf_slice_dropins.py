#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Snapshot, restore, and audit perf.slice drop-ins around a D348 hold."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


def parse_drop_in_paths(value: str) -> list[str]:
    """Parse systemd's space-separated DropInPaths property without rewriting paths."""
    paths = value.split()
    if len(paths) != len(set(paths)):
        raise ValueError("DropInPaths contains a duplicate path")
    if any(not Path(path).is_absolute() for path in paths):
        raise ValueError("DropInPaths contains a non-absolute path")
    return paths


def _read_file(path: Path) -> tuple[bytes, os.stat_result]:
    """Read one regular drop-in without following symlinks or changing its atime."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    noatime = getattr(os, "O_NOATIME", 0)
    try:
        descriptor = os.open(path, flags | noatime)
    except PermissionError:
        descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"drop-in is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ino,
        ):
            raise RuntimeError(f"drop-in changed while being captured: {path}")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def _file_record(path: str, content: bytes, metadata: os.stat_result, artifact: Path) -> dict[str, Any]:
    """Describe exact drop-in bytes and the metadata needed to restore them."""
    return {
        "path": path,
        "sha256": hashlib.sha256(content).hexdigest(),
        "content_base64": base64.b64encode(content).decode("ascii"),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
        "artifact_path": str(artifact),
    }


def snapshot(
    drop_in_paths: str,
    allowed_cpus: str,
    output: Path,
    raw_dir: Path,
) -> dict[str, Any]:
    """Record exact paths, property value, bytes, and raw file copies."""
    paths = parse_drop_in_paths(drop_in_paths)
    raw_dir.mkdir(parents=True, exist_ok=False)
    files: list[dict[str, Any]] = []
    for index, raw_path in enumerate(paths):
        path = Path(raw_path)
        content, metadata = _read_file(path)
        artifact = raw_dir / f"drop-in-{index:02d}.conf.raw"
        artifact.write_bytes(content)
        files.append(_file_record(raw_path, content, metadata, artifact))

    value = {
        "schema_version": SCHEMA_VERSION,
        "unit": "perf.slice",
        "drop_in_paths_raw": drop_in_paths,
        "drop_in_paths": paths,
        "allowed_cpus": allowed_cpus,
        "files": files,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return value


def _snapshot_file_bytes(record: dict[str, Any]) -> bytes:
    """Decode saved bytes and reject a corrupt or hand-edited baseline."""
    try:
        content = base64.b64decode(record["content_base64"], validate=True)
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError(f"baseline has invalid content for {record.get('path', '?')}") from error
    digest = hashlib.sha256(content).hexdigest()
    if digest != record.get("sha256"):
        raise ValueError(f"baseline content hash is invalid for {record.get('path', '?')}")
    return content


def load_snapshot(path: Path) -> dict[str, Any]:
    """Read one supported baseline object and validate every saved byte string."""
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != SCHEMA_VERSION or value.get("unit") != "perf.slice":
        raise ValueError("unsupported perf.slice drop-in baseline")
    if value.get("drop_in_paths") != parse_drop_in_paths(value.get("drop_in_paths_raw", "")):
        raise ValueError("baseline DropInPaths string does not match its parsed paths")
    records = value.get("files")
    if not isinstance(records, list) or [record.get("path") for record in records] != value["drop_in_paths"]:
        raise ValueError("baseline files do not match the saved DropInPaths")
    for record in records:
        _snapshot_file_bytes(record)
    return value


def _same_file(path: Path, record: dict[str, Any]) -> tuple[bool, str]:
    """Compare file bytes and mode, owner, group, and mtime with one baseline row."""
    try:
        content, metadata = _read_file(path)
    except (OSError, ValueError, RuntimeError) as error:
        return False, str(error)
    expected_content = _snapshot_file_bytes(record)
    if content != expected_content:
        return False, f"content differs: {path}"
    expected_metadata = {
        "mode": record.get("mode"),
        "uid": record.get("uid"),
        "gid": record.get("gid"),
        "mtime_ns": record.get("mtime_ns"),
    }
    actual_metadata = {
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
    }
    if actual_metadata != expected_metadata:
        return False, f"metadata differs: {path} expected={expected_metadata} actual={actual_metadata}"
    return True, ""


def verify_snapshot(
    baseline: dict[str, Any], drop_in_paths: str, allowed_cpus: str
) -> list[str]:
    """Return every exact path, property, content, or file-metadata mismatch."""
    errors: list[str] = []
    try:
        actual_paths = parse_drop_in_paths(drop_in_paths)
    except ValueError as error:
        return [str(error)]
    if drop_in_paths != baseline["drop_in_paths_raw"]:
        errors.append(
            "DropInPaths differs: "
            f"expected={baseline['drop_in_paths_raw']!r} actual={drop_in_paths!r}"
        )
    if allowed_cpus != baseline["allowed_cpus"]:
        errors.append(
            f"AllowedCPUs differs: expected={baseline['allowed_cpus']!r} actual={allowed_cpus!r}"
        )
    if actual_paths != baseline["drop_in_paths"]:
        return errors
    for record in baseline["files"]:
        matches, detail = _same_file(Path(record["path"]), record)
        if not matches:
            errors.append(detail)
    return errors


def _restore_file(path: Path, record: dict[str, Any]) -> None:
    """Atomically restore bytes and the captured file metadata."""
    content = _snapshot_file_bytes(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.restore-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), int(record["uid"]), int(record["gid"]))
            os.fchmod(stream.fileno(), int(record["mode"]))
        os.utime(temporary, ns=(int(record["mtime_ns"]), int(record["mtime_ns"])))
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def restore_snapshot(
    baseline: dict[str, Any], current_drop_in_paths: str, control_dir: Path
) -> list[str]:
    """Restore only systemd's runtime control drop-ins changed during the hold."""
    current_paths = parse_drop_in_paths(current_drop_in_paths)
    baseline_paths = set(baseline["drop_in_paths"])
    control_dir = control_dir.absolute()
    actions: list[str] = []

    for raw_path in current_paths:
        path = Path(raw_path)
        if path.parent.absolute() != control_dir or raw_path in baseline_paths:
            continue
        if not os.path.lexists(path):
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"refusing to remove a non-regular runtime drop-in: {path}")
        path.unlink()
        actions.append(f"removed hold-created runtime drop-in {path}")

    for record in baseline["files"]:
        path = Path(record["path"])
        if path.parent.absolute() != control_dir:
            matches, detail = _same_file(path, record)
            if not matches:
                raise RuntimeError(f"refusing to overwrite a non-control drop-in: {detail}")
            continue
        matches, _ = _same_file(path, record)
        if not matches:
            _restore_file(path, record)
            actions.append(f"restored exact runtime drop-in {path}")

    for record in baseline["files"]:
        matches, detail = _same_file(Path(record["path"]), record)
        if not matches:
            raise RuntimeError(f"runtime drop-in restore failed: {detail}")
    return actions


def main() -> int:
    """Expose the three audited operations used by the pinned runner."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    capture = sub.add_parser("snapshot", help="capture a perf.slice baseline")
    capture.add_argument("--drop-in-paths", required=True)
    capture.add_argument("--allowed-cpus", required=True)
    capture.add_argument("--output", required=True, type=Path)
    capture.add_argument("--raw-dir", required=True, type=Path)

    restore = sub.add_parser("restore", help="restore saved runtime control drop-ins")
    restore.add_argument("--baseline", required=True, type=Path)
    restore.add_argument("--current-drop-in-paths", required=True)
    restore.add_argument("--control-dir", required=True, type=Path)

    verify = sub.add_parser("verify", help="verify an exact perf.slice baseline")
    verify.add_argument("--baseline", required=True, type=Path)
    verify.add_argument("--drop-in-paths", required=True)
    verify.add_argument("--allowed-cpus", required=True)
    args = parser.parse_args()

    try:
        if args.command == "snapshot":
            value = snapshot(args.drop_in_paths, args.allowed_cpus, args.output, args.raw_dir)
            print(
                "captured perf.slice baseline: "
                f"AllowedCPUs={value['allowed_cpus'] or '<empty>'} "
                f"DropInPaths={value['drop_in_paths_raw'] or '<none>'}"
            )
            return 0
        baseline = load_snapshot(args.baseline)
        if args.command == "restore":
            actions = restore_snapshot(baseline, args.current_drop_in_paths, args.control_dir)
            for action in actions:
                print(action)
            print("runtime drop-in bytes restored; reload systemd before auditing AllowedCPUs")
            return 0
        errors = verify_snapshot(baseline, args.drop_in_paths, args.allowed_cpus)
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 2
        print(
            "perf.slice baseline exact: "
            f"AllowedCPUs={baseline['allowed_cpus'] or '<empty>'} "
            f"DropInPaths={baseline['drop_in_paths_raw'] or '<none>'}"
        )
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"perf-slice-dropins: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
