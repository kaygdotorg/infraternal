"""J1116 slow-link reader (#146): the browser end of slow_link_probe.

Accepts one TCP connection, reads frames (u32 length, u64 sequence, u64 capture_ns, u8 keyframe,
then the bytes) and echoes each frame's sequence and capture time (16 bytes) as soon as it has
fully arrived. Prints a summary line when the probe closes the connection.
"""
import socket, struct, sys

host, port = sys.argv[1], int(sys.argv[2])
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(1)
print("READY", flush=True)
conn, _ = server.accept()
conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def exact(count):
    """Reads exactly `count` bytes, or returns None at end of stream."""
    data = bytearray()
    while len(data) < count:
        chunk = conn.recv(min(1 << 20, count - len(data)))
        if not chunk:
            return None
        data += chunk
    return bytes(data)


frames = keyframes = total = 0
while True:
    header = exact(21)
    if header is None:
        break
    length, sequence, capture, keyframe = struct.unpack(">IQQB", header)
    if exact(length) is None:
        break
    conn.sendall(struct.pack(">QQ", sequence, capture))
    frames += 1
    keyframes += keyframe
    total += 21 + length
print(f"READER frames={frames} keyframes={keyframes} bytes={total}", flush=True)
