"""Observe outgoing GotaTun handshake initiations on one disposable veth."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import socket
import struct
import time
from collections import Counter
from collections.abc import Sequence
from typing import Any


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
) -> dict[str, Any]:
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
    outgoing_udp_packets = 0
    endpoint_udp_packets = 0
    destination_ports: set[int] = set()
    endpoint_message_types: Counter[int] = Counter()
    endpoint_payload_sizes: Counter[int] = Counter()
    try:
        raw.bind((interface, 0))
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        raw.settimeout(0.001)
        deadline = time.monotonic() + duration_seconds
        outgoing = getattr(socket, "PACKET_OUTGOING", 4)

        def observe(frame: bytes, packet_address: tuple[Any, ...]) -> None:
            """Count one parsed outgoing UDP packet without retaining its payload."""
            nonlocal handshakes, outgoing_udp_packets, endpoint_udp_packets
            if packet_address[2] != outgoing:
                return
            parsed = _ipv4_udp_payload(frame)
            if parsed is None:
                return
            destination_port, payload_offset = parsed
            outgoing_udp_packets += 1
            destination_ports.add(destination_port)
            if destination_port != endpoint_port:
                return
            endpoint_udp_packets += 1
            payload_size = len(frame) - payload_offset
            endpoint_payload_sizes[payload_size] += 1
            if payload_size < 4:
                return
            message_type = int.from_bytes(frame[payload_offset : payload_offset + 4], "little")
            endpoint_message_types[message_type] += 1
            if message_type == 1:
                handshakes += 1

        def drain_burst() -> None:
            """Drain a bounded batch so handshakes cannot queue behind a full-rate data flow."""
            for _ in range(64):
                try:
                    frame, packet_address = raw.recvfrom(65_535)
                except TimeoutError:
                    return
                observe(frame, packet_address)

        # Drain between triggers: sending the whole storm first let hot data packets fill the
        # packet socket before the short handshake initiations were counted.
        for address in peer_addresses:
            sender.sendto(b"j526-handshake-storm", (address, 5203))
            drain_burst()
        while time.monotonic() < deadline:
            try:
                frame, packet_address = raw.recvfrom(65_535)
            except TimeoutError:
                continue
            observe(frame, packet_address)
    finally:
        sender.close()
        raw.close()
    return {
        "peer_packets_sent": len(peer_addresses),
        "handshake_initiation_count": handshakes,
        "outgoing_udp_packet_count": outgoing_udp_packets,
        "endpoint_udp_packet_count": endpoint_udp_packets,
        "observed_udp_destination_ports": sorted(destination_ports),
        "endpoint_udp_message_type_counts": {
            str(message_type): count
            for message_type, count in sorted(endpoint_message_types.items())
        },
        "endpoint_udp_payload_size_counts": {
            str(payload_size): count
            for payload_size, count in sorted(endpoint_payload_sizes.items())
        },
    }
