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
