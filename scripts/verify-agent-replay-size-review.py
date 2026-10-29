#!/usr/bin/env python3
"""Independent #257 geometry checks after daemon adoption and real ring-wrap Snapshot replay."""
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, event_object, fixture_state


def run(binary):
    state = fixture_state('rr257')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    try:
        client.open()
        client.attach()
        client.until(b'shim-test')
        # Select this writer before resizing; other viewers stage their geometry until typing.
        client.input(b"printf 'SELECTED_%s\\n' OK\n")
        client.until(b'SELECTED_OK')
        client.wait_ack()
        client.send(1, 0x12, struct.pack('<HHHH', 120, 40, 0, 0))
        client.input(b"stty -echo -opost; PS1=''; printf 'SIZED_%s' OK\n")
        client.until(b'SIZED_OK')
        client.wait_ack()

        def adopt(snapshot):
            client.kill()
            client.start()
            cursor = 0 if snapshot else client.out
            client.out = cursor
            client.credit_pending = client.credit_available = 0
            client.send(1, 0x16, client.id.bytes + struct.pack('<QQ', cursor, client.acked))
            # Ack follows the new Hello. Queue the viewer's own differing Resize before credit.
            while True:
                frame = client.read_without_inventory()
                if frame[:2] == (1, 0x13):
                    client.process(frame=frame)
                    break
                client.process(frame=frame)
            client.send(1, 0x12, struct.pack('<HHHH', 60, 20, 0, 0))
            client.send(1, 0x14, struct.pack('<I', 1048576))
            saw_snapshot = False
            while True:
                frame = client.read_without_inventory()
                saw_snapshot |= frame[:2] == (1, 0x15)
                if frame[:2] == (1, 0x33):
                    notice = event_object(frame[2])
                    if notice.get('type') == 'terminal.replay_complete':
                        assert (notice.get('cols'), notice.get('rows')) == (120, 40), notice
                        assert int(notice['out_seq']) == client.out, notice
                        assert saw_snapshot == snapshot, (saw_snapshot, snapshot)
                        print(f'adopted replay: snapshot={snapshot}, pre-Resize=120x40, viewer=60x20: PASS')
                        break
                client.process(frame=frame)

        adopt(False)
        # Restore the active writer to 120x40 and advance beyond the retained raw ring.
        client.send(1, 0x12, struct.pack('<HHHH', 120, 40, 0, 0))
        client.input(b"yes | head -c 12M; printf 'WRAPPED_%s' OK\n")
        client.until(b'WRAPPED_OK')
        client.wait_ack()
        assert client.out > 8 * 1024 * 1024
        adopt(True)
    finally:
        client.kill()
        cleanup(state)


if __name__ == '__main__':
    run(Path(sys.argv[sys.argv.index('--binary') + 1]))
