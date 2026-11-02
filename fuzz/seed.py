"""Reproducibly seed protocol parsers and the Mesh JSON boundary."""
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
vectors = sorted((root.parent / 'contracts/vectors/wire').glob('*.bin'))

def seed_mesh():
    corpus = root / 'corpus' / 'mesh_api_json'
    corpus.mkdir(parents=True, exist_ok=True)
    cases = [
        ('list', {}),
        ('node-enroll', {'name': 'db-1', 'public_key': [1] * 32}),
        ('node-observe', {'node_id': 1, 'last_rtt_us': 1234}),
        ('node-rename', {'node_id': 1, 'name': 'db-2'}),
        ('node-delete', {'node_id': 1}),
        ('tag-create', {'name': 'prod'}),
        ('tag-rename', {'name': 'prod', 'new_name': 'production'}),
        ('tag-delete', {'name': 'prod'}),
        ('member-add', {'tag': 'prod', 'node_id': 1}),
        ('member-remove', {'tag': 'prod', 'node_id': 1}),
        ('grant-create', {
            'name': 'web', 'from': {'Tag': 'prod'}, 'to': {'Node': 1}, 'both_ways': False,
        }),
        ('grant-move', {
            'name': 'web', 'side': 'to', 'endpoint': {'Tag': 'frontend'},
        }),
        ('grant-delete', {'name': 'web'}),
        ('grant-rename', {'name': 'web', 'new_name': 'web-prod'}),
        ('role-define', {
            'name': 'prod-grants', 'actions': ['mesh.manage_grants'], 'scopes': ['prod'],
        }),
        ('role-assign', {'user_id': 'mesh-user', 'role': 'prod-grants'}),
    ]
    for selector, (name, value) in enumerate(cases):
        payload = json.dumps(value, separators=(',', ':'), sort_keys=True).encode()
        (corpus / name).write_bytes(bytes([selector]) + payload)
        if name == 'grant-create':
            # Exercise explicit null separately from the valid omitted policy.
            null_policy = dict(value, ports=None)
            payload = json.dumps(null_policy, separators=(',', ':'), sort_keys=True).encode()
            (corpus / 'grant-null-policy').write_bytes(bytes([selector]) + payload)

def seed_relay():
    corpus = root / 'corpus' / 'relay_wire_decode'
    corpus.mkdir(parents=True, exist_ok=True)
    host = bytes(range(16))
    for name, frame in [
        ('link', bytes([0x01]) + host),
        ('unlink', bytes([0x02]) + host),
        ('linked', bytes([0x81]) + host + (1).to_bytes(4, 'big')),
        ('linked-zero-id', bytes([0x81]) + host + bytes(4)),
        ('unlinked', bytes([0x82]) + host),
        ('link-trailing-byte', bytes([0x01]) + host + b'\x00'),
        ('datagram', (1).to_bytes(4, 'big') + b'\x01\x00\x00\x00ciphertext'),
        ('datagram-empty-payload', (1).to_bytes(4, 'big')),
        ('datagram-zero-id', bytes(4) + b'ciphertext'),
        ('datagram-short-id', b'\x00\x00\x01'),
        ('host-uri', b'urn:infraternal:host:01234567-89ab-cdef-0123-456789abcdef'),
    ]:
        (corpus / name).write_bytes(frame)

if sys.argv[1:] == ['--mesh-only']:
    seed_mesh()
    raise SystemExit(0)

if sys.argv[1:] == ['--relay-only']:
    seed_relay()
    raise SystemExit(0)

def seed_desktop_source(corpus):
    """Select the declared source action, then exercise its strict JSON body."""
    corpus.mkdir(parents=True, exist_ok=True)
    session_id = '00000000-0000-0000-0000-000000000001'
    start = {'session_id': session_id, 'start': {
        'target': {'type': 'screen', 'display_id': 1},
        'size': {'width': 960, 'height': 600, 'canvas_width': 960.0,
                 'canvas_height': 600.0, 'backing_scale': 1.0},
    }}
    cases = [
        ('up', 0, {}), ('down', 1, {}), ('component-status', 2, {}),
        ('start', 3, start), ('stop', 4, {'session_id': session_id}),
        ('inventory', 5, {}), ('cursor', 5, {'cursor': 'snapshot:17'}),
        ('source-status', 6, {'session_id': session_id}),
        ('clock', 7, {}), ('session-clock', 7, {'session_id': session_id}),
    ]
    for name, selector, value in cases:
        payload = json.dumps(value, separators=(',', ':')).encode()
        (corpus / name).write_bytes(bytes([selector]) + payload)
        if name == 'start':
            payload = payload.replace(b'"width":960', b'"width":960,"width":960')
            (corpus / 'duplicate-size').write_bytes(bytes([selector]) + payload)
    window_start = {'session_id': session_id, 'start': {
        'target': {'type': 'window', 'window_id': 17, 'owner_pid': 123},
        'size': {'width': 1280, 'height': 720, 'canvas_width': 640.0,
                 'canvas_height': 360.0, 'backing_scale': 2.0},
    }}
    payload = json.dumps(window_start, separators=(',', ':')).encode()
    (corpus / 'window-retina-start').write_bytes(b'\x03' + payload)
    (corpus / 'invalid-window-owner').write_bytes(b'\x03' + payload.replace(b'"owner_pid":123', b'"owner_pid":0'))
    for name, floor in [('sequence-floor', 41), ('exhausted-floor', 2**64 - 1), ('overflow-floor', 2**64)]:
        floored = dict(start, sequence_floor=floor)
        (corpus / name).write_bytes(b'\x03' + json.dumps(floored, separators=(',', ':')).encode())
    (corpus / 'duplicate-null').write_bytes(b'\x06{"session_id":null,"session_id":null}')
    (corpus / 'non-object').write_bytes(b'\x00[]')
    (corpus / 'foreign-runtime').write_bytes(b'\x00{"runtime":"untrusted"}')
    (corpus / 'exact-bound').write_bytes(b'\x00{}' + b' ' * (8192 - 2))
    (corpus / 'over-bound').write_bytes(b'\x00{}' + b' ' * (8193 - 2))

if sys.argv[1:2] == ['--desktop-source-only']:
    corpus = Path(sys.argv[2]) if len(sys.argv) == 3 else root / 'corpus' / 'desktop_source_json'
    seed_desktop_source(corpus)
    raise SystemExit(0)

def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result

for target in ['wire_frame_decode', 'wire_stream_decode']:
    corpus = root / 'corpus' / target
    corpus.mkdir(parents=True, exist_ok=True)
    for vector in vectors:
        raw = vector.read_bytes()
        (corpus / vector.stem).write_bytes(raw)
        for stream in [0, 127, 128, 16384, 2097152, 268435456, 0xffffffff]:
            mux = varint(stream) + raw
            (corpus / f'{vector.stem}-{stream}').write_bytes(mux)
            if target == 'wire_stream_decode':
                (corpus / f'{vector.stem}-{stream}-twice').write_bytes(mux + mux)
    (corpus / 'split-close').write_bytes(bytes([0, 3, 15, 0, 0] * 2))
    (corpus / 'split-credit-close').write_bytes(bytes([0, 5, 20, 1, 0, 0, 0, 0, 3, 15, 0, 0]))

# Shim capability bit 0: seed every additive frame and overflow/duplicate input.
shim = root / 'corpus' / 'shim_frame_decode'
shim.mkdir(parents=True, exist_ok=True)
for kind, payload in [
    (0x17, (0).to_bytes(8, 'little') + b'abc'),
    (0x17, (0xffffffffffffffff).to_bytes(8, 'little') + b'xx'),
    (0x18, (3).to_bytes(8, 'little')),
    (0x19, b''),
    (0x1a, (3).to_bytes(8, 'little') + (5).to_bytes(8, 'little')),
]:
    raw = bytes([kind]) + payload
    name = f'cap0-{kind:x}-{len(payload)}'
    (shim / name).write_bytes(raw)
    framed = len(raw).to_bytes(4, 'little') + raw
    (shim / f'{name}-framed').write_bytes(framed)
    (shim / f'{name}-twice').write_bytes(framed + framed)

# Additive multi-writer selection: exercise every fixed-width identity byte.
for writer in [0, 1, 0x01020304, 0xffffffff]:
    raw = bytes([0x1b]) + writer.to_bytes(4, 'little')
    framed = len(raw).to_bytes(4, 'little') + raw
    for suffix, value in [('raw', raw), ('framed', framed), ('twice', framed + framed)]:
        (shim / f'cap1-writer-{writer:x}-{suffix}').write_bytes(value)

# Approximate snapshots use bit 2 and type 28, distinct from deployed writer identity.
for flags in [0, 1, 2, 255]:
    for length in [0, 1, 64, 1024]:
        raw = bytes([0x1c]) + (17).to_bytes(8, 'little') + bytes([flags]) + bytes(length)
        framed = len(raw).to_bytes(4, 'little') + raw
        for suffix, value in [('raw', raw), ('framed', framed), ('twice', framed + framed)]:
            (shim / f'cap2-snapshot-{flags}-{length}-{suffix}').write_bytes(value)

seed_mesh()
seed_relay()
