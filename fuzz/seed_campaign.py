"""Write the small synthetic seed corpora of the targets added by the 2026-11-21 fuzz campaign (#561).

Run from anywhere: `python3 fuzz/seed_campaign.py`. Seeds go to
`fuzz/corpus/<target>/` and are replayed by each hook's unit test, so
`cargo test` exercises every target's entry function on the stable
toolchain (ENGINEERING P5). Every value here is synthetic: no captured
traffic, credentials or real host data.
"""
import json
from pathlib import Path

root = Path(__file__).resolve().parent
wire = sorted((root.parent / 'contracts/vectors/wire').glob('*.bin'))


def corpus(name):
    """The seed folder of one target, created empty if needed."""
    path = root / 'corpus' / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def message(tag, payload):
    """One WebSocket message in the terminal_stream_receive layout: tag, u16 length, payload."""
    return bytes([tag]) + len(payload).to_bytes(2, 'big') + payload


# terminal_stream_receive: stream-0 golden frames split across Binary
# messages, with Ping/Pong around them, then a Close; plus the open bodies.
seeds = corpus('terminal_stream_receive')
for vector in wire:
    frame = b'\x00' + vector.read_bytes()
    half = len(frame) // 2
    sample = message(0, frame[:half]) + message(4, b'p') + message(1, frame[half:]) + message(5, b'')
    (seeds / f'{vector.stem}-split').write_bytes(b'\x00' + sample + message(7, b'window closed'))
    (seeds / f'{vector.stem}-twice').write_bytes(b'\x00' + message(0, frame + frame))
(seeds / 'text-refused').write_bytes(b'\x00' + message(6, b'{}'))
(seeds / 'open-terminal').write_bytes(b'\x80' + json.dumps({'cols': 80, 'rows': 24, 'px_w': 0, 'px_h': 0}).encode())
(seeds / 'open-startup-get').write_bytes(b'\x80{"op":"get"}')

# agent_control_messages: control-socket frames, names, replies, Hello tokens.
seeds = corpus('agent_control_messages')
for vector in wire:
    frame = b'\x00' + vector.read_bytes()
    (seeds / f'socket-{vector.stem}').write_bytes(b'\x00\x03\x00\x01\x05' + frame)
(seeds / 'names').write_bytes(b'\x01' + json.dumps({'00000000-0000-4000-8000-000000000001': {'name': 'build', 'uid': 1000}}).encode())
(seeds / 'reply').write_bytes(b'\x02' + json.dumps({'code': 0, 'message': 'ok', 'next': '', 'data': {}}).encode())
# Found by the campaign (#561): an integer beyond u64 becomes a float that
# serde_json's default parser reads back one ULP off.
(seeds / 'reply-integer-beyond-u64').write_bytes(b'\x02{"code":0,"message":"","next":"","data":555558558355585583686}')
for token in ['linux', 'macos', 'freebsd', 'MacOS', '']:
    (seeds / f'hello-{token or "empty"}').write_bytes(b'\x03' + f'infraternal agent os={token}'.encode())
for text in ['linux direct=none', 'macos direct=none', 'linux direct=none ', 'linux  direct=none', 'direct=none']:
    (seeds / f"hello-{text.replace(' ', '_')}").write_bytes(b'\x03' + f'infraternal agent os={text}'.encode())

# remote_join_approval: a join body, an approval request with a poll token, a secret.
seeds = corpus('remote_join_approval')
host = '00000000-0000-4000-8000-000000000002'
(seeds / 'join').write_bytes(b'\x00' + json.dumps({'host_id': host, 'mode': 'rootless', 'token': 'A' * 43, 'csr_der': 'MAA'}).encode())
token = 'A' * 43
request = {'host_id': host, 'hostname': 'build-01', 'mode': 'user', 'execution_uid': 1000,
           'key_fingerprint': 'SHA256:' + 'A' * 43}
(seeds / 'approve').write_bytes(b'\x01' + bytes([len(token)]) + token.encode() + json.dumps(request).encode())
(seeds / 'secret').write_bytes(b'\x02' + b'A' * 43)

# desktop_reassembly: two frames (keyframe then delta), every fragment in order.
seeds = corpus('desktop_reassembly')
specs = bytes([0x80, 0x08, 0x00, 0x11, 0x00, 0x04, 0x00, 0x22])
(seeds / 'in-order').write_bytes(b'\x01' + specs + bytes(sum(([0, i] for i in range(3)), [])) + bytes(sum(([1, i] for i in range(2)), [])))
(seeds / 'lost-then-keyframe').write_bytes(b'\x01' + specs + bytes([1, 0, 0, 0, 0xE0, 0, 0, 1, 0, 2]))

# vt_stream_snapshot: plain text, an unfinished OSC across a resize, colours.
seeds = corpus('vt_stream_snapshot')
(seeds / 'text').write_bytes(bytes([80, 0, 2, 0, 3]) + b'hello\r\nworld\r\n')
(seeds / 'osc-resize').write_bytes(bytes([80, 1, 1, 2]) + b'\x1b]0;title' + b'\xfe\xfe\x28' + b'\x07done\r\n')
(seeds / 'sgr').write_bytes(bytes([40, 1, 0]) + b'\x1b[1;31mred\x1b[0m \x1b[?1049hfull\x1b[?1049l')
# A 50-column line at 20x5 whose middle row is the screen's top row, so the
# top row continues the last history row (#521, J1238); then a resize that
# reflows the crossing line, and further output. Size byte 19 is 20x5.
boundary = b'0\r\n1\r\n2\r\n' + b'x' * 50 + b'\r\nA\r\nB\r\nC'
(seeds / 'boundary-wrap').write_bytes(bytes([19, 1, 0]) + boundary + b'\xfe\xfe\x11' + b'more\r\n')
(seeds / 'boundary-wrap-wide').write_bytes(bytes([19, 1, 0]) + b'0\r\n1\r\n2\r\na' + '界'.encode() * 30 + b'\r\nA\r\nB\r\nC' + b'\xfe\xfe\x0b' + b'tail')

# ssh_packet_read: clear packets, then an AEAD key change, plus hostile tail.
seeds = corpus('ssh_packet_read')
(seeds / 'clear').write_bytes(bytes([0, 9, 2, 0, 3, 3]) + b'\x01\x15' + b'\x05hello' + b'\xff')
(seeds / 'rekey-gcm').write_bytes(bytes([15, 1, 1, 3]) + b'\x01\x15' + b'\x04ping' + b'\x02ok' + b'\xff' + b'\x00\x00\x00\x10junk')
(seeds / 'banner').write_bytes(bytes([0x80, 0, 0]) + b'\xff' + b'SSH-2.0-x\r\n\x00\x00\x00\x0c\x0a\x05hello' + b'\x00' * 10)
