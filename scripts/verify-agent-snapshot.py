#!/usr/bin/env python3
"""Tiny Snapshot credit never stalls independent shell progress [75][81], #118."""
import argparse
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state, varint
from credit_fixture import CreditObservation, completed


def run(binary):
    state = fixture_state('ts')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    observation = None
    try:
        client.open()
        client.attach()
        client.wait_for_shell()
        client.input(b"stty -echo -opost; PS1=''; printf 'READY_%s' OK\n")
        client.until(b'READY_OK')
        client.wait_ack()
        client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        client.fence()
        observation = CreditObservation(state, client.id)
        client.attach()
        for iteration in range(3):
            marker = state.resolve() / f'completed-{iteration}'
            disconnects = observation.disconnects
            client.input(f"yes | head -c 12M; : > '{marker}'\n".encode())
            # Consume every byte funded on this attachment before capturing the
            # cursor. A quiet socket can still have almost a whole window in flight.
            client.drain_credit()
            observation.detached_after(disconnects)
            completed(marker)
            client.fence()
            count = len(client.snapshots)
            cursor = client.out
            notices = len(client.events)
            disconnects = observation.disconnects
            repaints = len(observation.repaints)
            client.send(1, 0x14, struct.pack('<I', 1))
            # Observe recovery reaching an unaffordable repaint and detaching.
            # The relay unit tests assert the exact starvation timer boundary.
            observation.detached_after(disconnects)
            assert len(observation.repaints) == repaints + 1
            assert observation.repaints[-1] > 1
            client.fence()
            assert len(client.snapshots) == count and client.out == cursor
            assert len(client.events) == notices
            client.send(1, 0x14, struct.pack('<I', 1024 * 1024))
            while len(client.snapshots) == count:
                client.process(credit=False)
            client.fence()
            assert len(client.snapshots) == count + 1
            assert client.snapshots[-1][1] > 1
            print(f'catch-up {iteration}: 12 MiB shell completed; 1-byte credit paused; funded Snapshot={client.snapshots[-1][1]} bytes seq={client.out}: PASS', flush=True)
        # Preserve the original fourth flood and its lack of any further grant.
        marker = state.resolve() / 'final'
        disconnects = observation.disconnects
        client.input(f"yes | head -c 12M; : > '{marker}'\n".encode())
        client.drain_credit()
        observation.detached_after(disconnects)
        completed(marker)
        client.fence()
        # EOF plus the drained credit window proves no old viewer Output remains.
        # Only then retire the stream, reset its cursor and test ring-wrap attach.
        client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        client.fence()
        client.out = 0
        count = len(client.snapshots)
        client.attach()
        while len(client.snapshots) == count:
            client.process(credit=False)
        client.fence()
        assert len(client.snapshots) == count + 1
        assert client.out > 8 * 1024 * 1024
        print(f'initial ring-wrap attachment: Snapshot={client.snapshots[-1][1]} bytes seq={client.out}: PASS', flush=True)
        print('four 12 MiB floods completed; three tiny-credit pauses and funded Snapshots; no Close needed: PASS', flush=True)
    finally:
        client.kill()
        if observation is not None:
            observation.close()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
