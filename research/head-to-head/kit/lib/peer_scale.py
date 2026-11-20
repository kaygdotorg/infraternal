#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Add inert peer records for the #260 R4b memory-at-scale sample."""
import argparse
import base64
import binascii
import ipaddress
import json
import os
import secrets
import socket
from pathlib import Path

BASE = int(ipaddress.IPv4Address("100.64.0.0"))

def peer_ip(index: int) -> str:
    if not 0 <= index < (1 << 22):
        raise ValueError("peer index exceeds the reserved 100.64/10 test range")
    return f"{ipaddress.IPv4Address(BASE + index)}/32"

def add_uapi(args: argparse.Namespace) -> None:
    fields = ["set=1"]
    for index in range(args.start, args.start + args.count):
        fields.extend((
            f"public_key={secrets.token_hex(32)}",
            "replace_allowed_ips=true",
            f"allowed_ip={peer_ip(index)}",
        ))
    request = ("\n".join(fields) + "\n\n").encode("ascii")
    path = f"/var/run/wireguard/{args.interface}.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(30)
        stream.connect(path)
        stream.sendall(request)
        response = bytearray()
        while b"\n\n" not in response:
            chunk = stream.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    text = response.decode("ascii", errors="replace")
    if "errno=0" not in text:
        raise RuntimeError(f"UAPI peer update failed: {text[:500]}")
    print(json.dumps({"added": args.count, "interface": args.interface, "status": "ok"}))

def write_kernel_config(args: argparse.Namespace) -> None:
    active = (args.active_public, args.active_ip, args.active_endpoint)
    if any(active) and not all(active):
        raise ValueError("active peer public key, allowed IP, and endpoint must be supplied together")
    private_key_path = getattr(args, "interface_private_key_file", None)
    listen_port = getattr(args, "listen_port", None)
    if (private_key_path is None) != (listen_port is None):
        raise ValueError("interface private-key file and listen port must be supplied together")
    interface_private_key = None
    if private_key_path is not None:
        try:
            interface_private_key = Path(private_key_path).read_text(encoding="ascii").strip()
            private_key_bytes = base64.b64decode(interface_private_key, validate=True)
        except (OSError, UnicodeError, binascii.Error) as error:
            raise ValueError("interface private-key file must contain a base64 WireGuard key") from error
        if len(private_key_bytes) != 32:
            raise ValueError("interface private-key file must decode to exactly 32 bytes")
        if not isinstance(listen_port, int) or not 1 <= listen_port <= 65535:
            raise ValueError("interface listen port must be between 1 and 65535")
    lines = ["[Interface]"]
    if interface_private_key is not None:
        lines.extend(("", f"PrivateKey = {interface_private_key}", f"ListenPort = {listen_port}"))
    if all(active):
        lines.extend(("", "[Peer]", f"PublicKey = {base64.b64encode(bytes.fromhex(args.active_public)).decode('ascii')}",
                      f"Endpoint = {args.active_endpoint}", f"AllowedIPs = {args.active_ip}"))
    for index in range(args.start, args.start + args.count):
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        lines.extend(("", "[Peer]", f"PublicKey = {key}", f"AllowedIPs = {peer_ip(index)}"))
    path = Path(args.output)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write("\n".join(lines) + "\n")
    print(json.dumps({"configured_inert": args.count, "configured_total": args.count + int(all(active)), "output": str(path)}))

def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    uapi = sub.add_parser("add-uapi")
    uapi.add_argument("--interface", required=True)
    uapi.add_argument("--count", type=int, required=True)
    uapi.add_argument("--start", type=int, default=0)
    kernel = sub.add_parser("kernel-config")
    kernel.add_argument("--count", type=int, required=True)
    kernel.add_argument("--start", type=int, default=0)
    kernel.add_argument("--output", required=True)
    kernel.add_argument("--active-public")
    kernel.add_argument("--active-ip")
    kernel.add_argument("--active-endpoint")
    kernel.add_argument("--interface-private-key-file", type=Path)
    kernel.add_argument("--listen-port", type=int)
    args = parser.parse_args()
    if args.command == "add-uapi":
        add_uapi(args)
    else:
        write_kernel_config(args)

if __name__ == "__main__":
    main()
