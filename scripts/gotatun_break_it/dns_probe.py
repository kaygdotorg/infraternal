"""Query the node's high-port mesh DNS listener without host resolver state."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import ipaddress
import secrets
import socket
import struct

DNS_PORT = 1053
_HEADER = struct.Struct("!HHHHHH")
_QUESTION = struct.Struct("!HH")
_RECORD = struct.Struct("!HHIH")


def build_a_query(name: str, *, transaction_id: int) -> bytes:
    """Encode one bounded IN/A question using ASCII mesh host labels."""
    if type(transaction_id) is not int or not 0 <= transaction_id <= 0xFFFF:
        raise ValueError("DNS transaction IDs must fit in sixteen bits")
    canonical = name.rstrip(".")
    labels = canonical.split(".")
    if not labels or len(canonical) > 253 or any(
        not label or len(label.encode("ascii", errors="ignore")) != len(label) or len(label) > 63
        for label in labels
    ):
        raise ValueError("DNS names must contain bounded ASCII labels")
    question_name = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\0"
    return _HEADER.pack(transaction_id, 0x0100, 1, 0, 0, 0) + question_name + _QUESTION.pack(1, 1)


def _skip_name(packet: bytes, offset: int) -> int:
    """Return the next field after a DNS name, following pointers safely."""
    if offset < 0 or offset >= len(packet):
        raise ValueError("DNS name starts outside the response")
    next_offset = offset
    jumped = False
    visited = 0
    while True:
        if next_offset >= len(packet):
            raise ValueError("DNS name extends outside the response")
        length = packet[next_offset]
        if length & 0xC0 == 0xC0:
            if next_offset + 1 >= len(packet):
                raise ValueError("DNS compression pointer is truncated")
            pointer = ((length & 0x3F) << 8) | packet[next_offset + 1]
            if pointer >= len(packet):
                raise ValueError("DNS compression pointer is outside the response")
            if not jumped:
                offset = next_offset + 2
            next_offset = pointer
            jumped = True
            visited += 1
            if visited > 128:
                raise ValueError("DNS name has a compression pointer loop")
        elif length & 0xC0:
            raise ValueError("DNS label uses a reserved length encoding")
        elif length == 0:
            return offset if jumped else next_offset + 1
        else:
            next_offset += 1
            if next_offset + length > len(packet):
                raise ValueError("DNS label extends outside the response")
            next_offset += length


def parse_a_answers(packet: bytes, *, transaction_id: int) -> tuple[str, ...]:
    """Return valid IN/A answers after checking the response header and bounds."""
    if len(packet) < _HEADER.size:
        raise ValueError("DNS response is shorter than its header")
    response_id, flags, question_count, answer_count, _, _ = _HEADER.unpack_from(packet)
    if response_id != transaction_id:
        raise ValueError("DNS response transaction ID does not match the query")
    if flags & 0x8000 == 0:
        raise ValueError("DNS packet is not a response")
    if flags & 0x000F:
        raise ValueError(f"DNS response returned status {flags & 0x000F}")
    offset = _HEADER.size
    for _ in range(question_count):
        offset = _skip_name(packet, offset)
        if offset + _QUESTION.size > len(packet):
            raise ValueError("DNS question is truncated")
        offset += _QUESTION.size
    answers: list[str] = []
    for _ in range(answer_count):
        offset = _skip_name(packet, offset)
        if offset + _RECORD.size > len(packet):
            raise ValueError("DNS answer record is truncated")
        record_type, record_class, _, record_length = _RECORD.unpack_from(packet, offset)
        offset += _RECORD.size
        if offset + record_length > len(packet):
            raise ValueError("DNS answer data is truncated")
        data = packet[offset : offset + record_length]
        if record_type == 1 and record_class == 1 and record_length == 4:
            answers.append(str(ipaddress.IPv4Address(data)))
        offset += record_length
    return tuple(answers)


def query_a(server: str, name: str, *, timeout_seconds: float = 2.0) -> tuple[str, ...]:
    """Ask a peer's direct mesh DNS listener for one A record and validate its reply."""
    address = str(ipaddress.IPv4Address(server))
    if timeout_seconds <= 0:
        raise ValueError("DNS query timeout must be positive")
    transaction_id = secrets.randbelow(0x10000)
    query = build_a_query(name, transaction_id=transaction_id)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout_seconds)
        client.sendto(query, (address, DNS_PORT))
        response, source = client.recvfrom(4096)
    if source != (address, DNS_PORT):
        raise ValueError("DNS response came from a different mesh endpoint")
    return parse_a_answers(response, transaction_id=transaction_id)
