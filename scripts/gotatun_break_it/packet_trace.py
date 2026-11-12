"""Observe outgoing GotaTun handshake initiations on one disposable veth."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import socket
import struct
import time
from collections.abc import Sequence


def _ipv4_udp_payload(frame: bytes) -> tuple[int, int] | None:
    """Return the IPv4 UDP destination port and payload offset for one Ethernet frame."""
    if len(frame) < 14:
        return None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ether_type in {0x8100, 0x88A8, 0x9100}:
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None
    version_and_ihl = frame[offset]
    header_size = (version_and_ihl & 0x0F) * 4
    total_size = struct.unpack_from("!H", frame, offset + 2)[0]
    fragments = struct.unpack_from("!H", frame, offset + 6)[0]
    if (
        version_and_ihl >> 4 != 4
        or header_size < 20
        or frame[offset + 9] != socket.IPPROTO_UDP
        or fragments & 0x1FFF
        or total_size < header_size + 8
        or len(frame) < offset + min(total_size, header_size + 12)
    ):
        return None
    udp_offset = offset + header_size
    payload_offset = udp_offset + 8
    if total_size < header_size + 12:
        return None
    return struct.unpack_from("!H", frame, udp_offset + 2)[0], payload_offset


def is_wireguard_handshake_initiation(frame: bytes, *, destination_port: int | None = None) -> bool:
    """Recognize a complete IPv4 UDP datagram whose WireGuard message type is initiation."""
    parsed = _ipv4_udp_payload(frame)
    if parsed is None:
        return False
    port, payload_offset = parsed
    if destination_port is not None and port != destination_port:
        return False
    return int.from_bytes(frame[payload_offset : payload_offset + 4], "little") == 1


def trigger_handshake_storm(
    interface: str,
    peer_addresses: Sequence[str],
    *,
    endpoint_port: int,
    duration_seconds: float = 3.0,
) -> dict[str, int]:
    """Trigger one packet toward every simulated peer and count outgoing handshakes."""
    if interface not in {"underlay0", "underlay1"}:
        raise ValueError("handshake capture may only use a disposable underlay veth")
    if not peer_addresses:
        raise ValueError("handshake storm needs at least one peer")
    if type(endpoint_port) is not int or not 1 <= endpoint_port <= 65535:
        raise ValueError("handshake destination port must be valid")
    if duration_seconds <= 0:
        raise ValueError("handshake capture duration must be positive")
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    handshakes = 0
    try:
        raw.bind((interface, 0))
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        raw.settimeout(0.05)
        for address in peer_addresses:
            sender.sendto(b"j526-handshake-storm", (address, 5203))
        deadline = time.monotonic() + duration_seconds
        outgoing = getattr(socket, "PACKET_OUTGOING", 4)
        while time.monotonic() < deadline:
            try:
                frame, packet_address = raw.recvfrom(65_535)
            except TimeoutError:
                continue
            if packet_address[2] == outgoing and is_wireguard_handshake_initiation(
                frame,
                destination_port=endpoint_port,
            ):
                handshakes += 1
    finally:
        sender.close()
        raw.close()
    return {
        "peer_packets_sent": len(peer_addresses),
        "handshake_initiation_count": handshakes,
    }
