#!/usr/bin/env python3
# Role: scripted private companion that emits a startup delta and counts forced keyframe requests.
import json
import struct
import sys


def read_exact(count):
    data = bytearray()
    while len(data) < count:
        part = sys.stdin.buffer.read(count - len(data))
        if not part:
            return None
        data.extend(part)
    return bytes(data)


def read_frame():
    header = read_exact(6)
    if header is None:
        return None
    length, version, kind = struct.unpack(">IBB", header)
    assert version == 1 and 2 <= length <= 65536
    body = read_exact(length - 2)
    assert body is not None
    return kind, body


def send(kind, body):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    sys.stdout.buffer.write(struct.pack(">IBB", len(body) + 2, 1, kind) + body)
    sys.stdout.buffer.flush()


def video(stamp, keyframe):
    nal = b"\x00\x00\x00\x01\x65" if keyframe else b"\x00\x00\x00\x01\x41"
    send(70, struct.pack(">Q", stamp) + bytes([int(keyframe)]) + nal)


while True:
    request = read_frame()
    if request is None:
        break
    kind, _ = request
    if kind == 2:
        send(66, {"capture_rect": {"x": 0, "y": 0, "width": 64, "height": 48}})
        video(1, False)
    elif kind == 7:
        with open(sys.argv[0] + ".requests", "a", encoding="utf-8") as output:
            output.write("keyframe\n")
        video(2, True)
        send(68, {"keyframe_requested": True})
    elif kind == 5:
        send(68, {"restored": True})
        break
    else:
        send(68, {"state": "on"})
