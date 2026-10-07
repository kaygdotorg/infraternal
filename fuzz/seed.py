"""Reproducibly seed both fuzz targets from all golden frames and mux-id widths."""
from pathlib import Path

root = Path(__file__).resolve().parent
vectors = sorted((root.parent / 'contracts/vectors/wire').glob('*.bin'))

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
