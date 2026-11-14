#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Create ephemeral test keys and configure a userspace WireGuard UAPI peer.

The private material stays in the case's private tmpfs directory and is sent
only over the interface's Unix socket. This helper exists only for the #260
userspace dataplane measurement.
"""

import argparse
import os
import secrets
import socket
import subprocess
import tempfile
from pathlib import Path


# PKCS#8 encodes this raw X25519 seed after the standard algorithm identifier.
PKCS8_X25519_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")


def write_private(path: Path, value: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value.hex().encode("ascii") + b"\n")


def make_keypair(directory: Path, name: str) -> None:
    private = secrets.token_bytes(32)
    with tempfile.TemporaryDirectory(prefix="key-", dir=directory) as tmp:
        der = Path(tmp) / "private.der"
        fd = os.open(der, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(PKCS8_X25519_PREFIX + private)
        public_der = subprocess.run(
            ["openssl", "pkey", "-inform", "DER", "-in", str(der), "-pubout", "-outform", "DER"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    if len(public_der) < 32:
        raise RuntimeError("OpenSSL returned a truncated X25519 public key")
    write_private(directory / f"{name}.private", private)
    write_private(directory / f"{name}.public", public_der[-32:])


def configure(args: argparse.Namespace) -> None:
    private = Path(args.private_key).read_text(encoding="ascii").strip()
    peer = Path(args.peer_public).read_text(encoding="ascii").strip()
    if len(private) != 64 or len(peer) != 64:
        raise RuntimeError("WireGuard keys must contain 32 bytes")

    fields = [
        "set=1",
        f"private_key={private}",
        f"listen_port={args.listen_port}",
        "replace_peers=true",
        f"public_key={peer}",
        f"endpoint={args.endpoint}",
        "replace_allowed_ips=true",
        f"allowed_ip={args.allowed_ip}",
        "",
    ]
    # UAPI commands end with a blank line, not a single line terminator.
    request = ("\n".join(fields) + "\n").encode("ascii")
    path = f"/var/run/wireguard/{args.interface}.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(path)
        stream.sendall(request)
        response = bytearray()
        while b"\n\n" not in response:
            chunk = stream.recv(1024)
            if not chunk:
                break
            response.extend(chunk)
    text = response.decode("ascii", errors="replace")
    if "errno=0" not in text:
        raise RuntimeError(f"GotaTun UAPI configuration failed: {text.strip()}")


def peer_update(args: argparse.Namespace) -> None:
    """Remove and restore one peer without setting an engine-specific keepalive."""
    peer = Path(args.peer_public).read_text(encoding="ascii").strip()
    if len(peer) != 64:
        raise RuntimeError("WireGuard public key must contain 32 bytes")
    path = f"/var/run/wireguard/{args.interface}.sock"
    requests = (
        ("set=1", f"public_key={peer}", "remove=true", ""),
        ("set=1", f"public_key={peer}", f"endpoint={args.endpoint}",
         "replace_allowed_ips=true", f"allowed_ip={args.allowed_ip}", ""),
    )
    for fields in requests:
        request = ("\n".join(fields) + "\n").encode("ascii")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(5)
            stream.connect(path)
            stream.sendall(request)
            response = bytearray()
            while b"\n\n" not in response:
                chunk = stream.recv(1024)
                if not chunk:
                    break
                response.extend(chunk)
        text = response.decode("ascii", errors="replace")
        if "errno=0" not in text:
            raise RuntimeError(f"WireGuard UAPI peer update failed: {text.strip()}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    keys = sub.add_parser("keys")
    keys.add_argument("directory")
    setup = sub.add_parser("configure")
    setup.add_argument("--interface", required=True)
    setup.add_argument("--private-key", required=True)
    setup.add_argument("--peer-public", required=True)
    setup.add_argument("--endpoint", required=True)
    setup.add_argument("--listen-port", type=int, required=True)
    setup.add_argument("--allowed-ip", required=True)
    reset = sub.add_parser("peer-update")
    reset.add_argument("--interface", required=True)
    reset.add_argument("--peer-public", required=True)
    reset.add_argument("--endpoint", required=True)
    reset.add_argument("--allowed-ip", required=True)
    args = parser.parse_args()

    if args.command == "keys":
        directory = Path(args.directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        make_keypair(directory, "a")
        make_keypair(directory, "b")
    elif args.command == "configure":
        configure(args)
    else:
        peer_update(args)


if __name__ == "__main__":
    main()
