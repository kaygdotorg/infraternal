#!/usr/bin/env python3
"""Fetches the pinned Traefik release and prepares a bounded component manifest [#281]."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from tarfile import ReadError, open as open_tar
from typing import BinaryIO

TRAEFIK_VERSION = "3.7.17"
MAX_CHECKSUM_BYTES = 64 * 1024
MAX_COMPONENT_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_COMPONENT_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_CHANGELOG_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 256
MAX_LICENSE_BYTES = 1024 * 1024
ALLOWLISTED_ARCHIVE_MEMBERS = frozenset({"traefik", "LICENSE.md", "CHANGELOG.md"})
CHUNK_BYTES = 64 * 1024
SUPPORTED_TARGETS = {
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
}
REDIRECT_HOSTS = {
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}


def parse_checksums(text: str) -> dict[str, str]:
    """Parse the upstream SHA-256 list, rejecting ambiguity and unsafe names."""
    if not text or len(text.encode("utf-8")) > MAX_CHECKSUM_BYTES:
        raise ValueError("Traefik checksum list is empty or exceeds its bound")
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})[ \t]+\*?([^\s]+)", line)
        if match is None:
            raise ValueError("Traefik checksum list has an invalid row")
        digest, filename = match.groups()
        if (
            filename in {".", ".."}
            or "/" in filename
            or "\\" in filename
            or filename in parsed
        ):
            raise ValueError("Traefik checksum list has an unsafe or duplicate filename")
        parsed[filename] = digest.lower()
    if not parsed:
        raise ValueError("Traefik checksum list contains no assets")
    return parsed


def verify_checksum(stream: BinaryIO, checksums: dict[str, str], filename: str) -> tuple[str, int]:
    """Hash an upstream archive while enforcing the component-specific byte cap."""
    expected = checksums.get(filename)
    if expected is None or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Traefik checksum list does not name the pinned archive")
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(CHUNK_BYTES):
        size += len(chunk)
        if size > MAX_COMPONENT_ARCHIVE_BYTES:
            raise ValueError("Traefik archive exceeds the component payload bound")
        digest.update(chunk)
    actual = digest.hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("Traefik archive does not match its published SHA-256")
    if size == 0:
        raise ValueError("Traefik archive is empty")
    return actual, size


def inspect_archive(stream: BinaryIO) -> dict[str, str | int]:
    """Inspect only the exact regular members accepted by the node installer."""
    names: set[str] = set()
    executable_digest: str | None = None
    executable_size: int | None = None
    license_present = False
    license_text = bytearray()
    total_size = 0
    entry_count = 0
    try:
        with open_tar(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                entry_count += 1
                if entry_count > MAX_ARCHIVE_ENTRIES:
                    raise ValueError("Traefik archive has too many entries")
                name = member.name
                parts = name.split("/")
                if (
                    not name
                    or name.startswith("/")
                    or "\\" in name
                    or any(part in {"", ".", ".."} for part in parts)
                    or len(parts) != 1
                    or name in names
                ):
                    raise ValueError("Traefik archive contains an unsafe or duplicate path")
                if name not in ALLOWLISTED_ARCHIVE_MEMBERS:
                    raise ValueError("Traefik archive contains an unallowlisted path")
                names.add(name)
                if not member.isfile() or member.mode & 0o6000:
                    raise ValueError("Traefik archive contains a non-regular or privileged entry")
                if member.size < 0 or member.size > MAX_COMPONENT_EXECUTABLE_BYTES:
                    raise ValueError("Traefik archive entry exceeds the component payload bound")
                if name == "CHANGELOG.md" and member.size > MAX_CHANGELOG_BYTES:
                    raise ValueError("Traefik changelog exceeds its byte bound")
                total_size += member.size
                if total_size > (
                    MAX_COMPONENT_EXECUTABLE_BYTES + MAX_LICENSE_BYTES + MAX_CHANGELOG_BYTES
                ):
                    raise ValueError("Traefik archive expands beyond the component payload bound")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("Traefik archive entry could not be read")
                digest = hashlib.sha256()
                read_size = 0
                while chunk := source.read(CHUNK_BYTES):
                    read_size += len(chunk)
                    if read_size > member.size:
                        raise ValueError("Traefik archive entry exceeds its declared size")
                    if name == "traefik":
                        digest.update(chunk)
                    elif name == "LICENSE.md":
                        license_present = True
                        if len(license_text) + len(chunk) > MAX_LICENSE_BYTES:
                            raise ValueError("Traefik license file exceeds its bound")
                        license_text.extend(chunk)
                if read_size != member.size:
                    raise ValueError("Traefik archive entry is truncated")
                if name == "traefik":
                    executable_digest = digest.hexdigest()
                    executable_size = read_size
        if executable_digest is None or executable_size is None:
            raise ValueError("Traefik archive does not contain its executable")
        if not license_present or b"MIT License" not in license_text:
            raise ValueError("Traefik archive does not contain the expected MIT license")
    except (ReadError, OSError, EOFError) as error:
        raise ValueError("Traefik archive is malformed") from error
    return {
        "executable_sha256": executable_digest,
        "executable_size": executable_size,
        "license": "MIT",
    }


def _read_response(url: str, maximum: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "infraternal-release-builder"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in REDIRECT_HOSTS:
                raise ValueError("Traefik download redirected to an untrusted host")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > maximum:
                raise ValueError("Traefik download exceeds its size bound")
            chunks = bytearray()
            while chunk := response.read(CHUNK_BYTES):
                if len(chunks) + len(chunk) > maximum:
                    raise ValueError("Traefik download exceeds its size bound")
                chunks.extend(chunk)
            return bytes(chunks)
    except (OSError, TimeoutError) as error:
        raise ValueError("Traefik release download failed") from error


def _write_atomically(path: Path, content: bytes, mode: int = 0o644) -> None:
    _write_stream_atomically(path, io.BytesIO(content), mode)


def _write_stream_atomically(path: Path, content: BinaryIO, mode: int = 0o644) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            while chunk := content.read(CHUNK_BYTES):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _validate_target(release_version: str, os_name: str, arch: str) -> None:
    if (os_name, arch) not in SUPPORTED_TARGETS:
        raise ValueError("Traefik target is not supported")
    if not re.fullmatch(r"(?:[0-9]+\.[0-9]+\.[0-9]+|edge-[0-9]{8}T[0-9]{6}Z)", release_version):
        raise ValueError("infraternal release identity is invalid")


def write_component_bundle(
    release_version: str,
    os_name: str,
    arch: str,
    archive_stream: BinaryIO,
    checksum_text: str,
    output: Path,
) -> Path:
    """Verify a pinned upstream stream, then atomically write its manifest and mirror payload."""
    _validate_target(release_version, os_name, arch)
    filename = f"traefik_v{TRAEFIK_VERSION}_{os_name}_{arch}.tar.gz"
    checksums = parse_checksums(checksum_text)
    with tempfile.SpooledTemporaryFile(max_size=4 * 1024 * 1024, mode="w+b") as staged:
        digest = hashlib.sha256()
        size = 0
        expected = checksums.get(filename)
        if expected is None:
            raise ValueError("Traefik checksum list does not name the pinned archive")
        while chunk := archive_stream.read(CHUNK_BYTES):
            size += len(chunk)
            if size > MAX_COMPONENT_ARCHIVE_BYTES:
                raise ValueError("Traefik archive exceeds the component payload bound")
            digest.update(chunk)
            staged.write(chunk)
        archive_digest = digest.hexdigest()
        if size == 0 or not hmac.compare_digest(archive_digest, expected):
            raise ValueError("Traefik archive does not match its published SHA-256")
        staged.seek(0)
        inspected = inspect_archive(staged)
        staged.seek(0)

        mirror_path = f"components/{release_version}/proxy/{os_name}/{arch}/{filename}"
        manifest = {
            "component": "traefik",
            "version": TRAEFIK_VERSION,
            "release_version": release_version,
            "os": os_name,
            "arch": arch,
            "archive_filename": filename,
            "archive_url": (
                f"https://github.com/traefik/traefik/releases/download/v{TRAEFIK_VERSION}/{filename}"
            ),
            "mirror_path": mirror_path,
            "archive_sha256": archive_digest,
            "archive_size": size,
            **inspected,
        }
        manifest_path = output / f"proxy-traefik-{os_name}-{arch}.json"
        _write_stream_atomically(output / mirror_path, staged)
        _write_atomically(
            manifest_path,
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )
        return manifest_path


def build_component(release_version: str, os_name: str, arch: str, output: Path) -> Path:
    """Fetch and verify one pinned upstream target, then write its mirror bundle."""
    _validate_target(release_version, os_name, arch)
    filename = f"traefik_v{TRAEFIK_VERSION}_{os_name}_{arch}.tar.gz"
    base = f"https://github.com/traefik/traefik/releases/download/v{TRAEFIK_VERSION}"
    checksums_url = f"{base}/traefik_v{TRAEFIK_VERSION}_checksums.txt"
    checksums = parse_checksums(_read_response(checksums_url, MAX_CHECKSUM_BYTES).decode("ascii"))
    url = f"{base}/{filename}"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in REDIRECT_HOSTS:
                raise ValueError("Traefik download redirected to an untrusted host")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_COMPONENT_ARCHIVE_BYTES:
                raise ValueError("Traefik download exceeds its size bound")
            return write_component_bundle(
                release_version, os_name, arch, response, "\n".join(
                    f"{digest}  {name}" for name, digest in checksums.items()
                ) + "\n", output
            )
    except (OSError, TimeoutError) as error:
        raise ValueError("Traefik release download failed") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--os", choices=sorted({target[0] for target in SUPPORTED_TARGETS}), required=True)
    parser.add_argument("--arch", choices=sorted({target[1] for target in SUPPORTED_TARGETS}), required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        manifest = build_component(arguments.release_version, arguments.os, arguments.arch, arguments.output)
    except (OSError, ValueError, UnicodeError) as error:
        parser.error(str(error))
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
