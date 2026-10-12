#!/usr/bin/env python3
"""Real daemon idle and unattached/adopted shim exit census measurements for #168 [D81]."""
import argparse
import os
from pathlib import Path
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_fixture import Binary, cleanup, fixture_state, rss
from idle_canary import assert_process_idle, session_shim_pid


def census(client, session_id, present, deadline):
    """Read only pushed census frames; no inbound traffic can cause discovery."""
    previous_timeout = client.sock.gettimeout()
    try:
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'missing event-driven census'
            client.sock.settimeout(remaining)
            frame = client.read()
            assert frame[:2] == (0, 0x33), f'unexpected unsolicited frame {frame[:2]}'
            client.process(frame=frame)
            if (str(session_id) in client.inventory['session_ids']) == present:
                return
    finally:
        client.sock.settimeout(previous_timeout)


def idle(client, label, sessions):
    # Startup and exit cleanup can still resume after its last Pong is written.
    # Settle that finite work in the probe, then keep the full zero-activation
    # assertion. A daemon timer would still fail the unchanged 2.2 s window.
    time.sleep(0.1)
    result = assert_process_idle(client.child.pid, label)
    print(f'event_idle label={label!r} sessions={sessions} slices={result.total_slices} '
          f'seconds={result.elapsed_seconds:.3f} rss_kib={rss(client.child.pid)}', flush=True)


def run(binary, samples):
    state = fixture_state('ee')
    state.mkdir(mode=0o700)
    client = Binary.__new__(Binary)
    latencies = []
    try:
        client.__init__(binary, state)
        idle(client, 'empty infraternal agent', 0)
        for index in range(samples):
            client.open()
            session_id = client.id
            # open already requires the positive census before its Result.
            assert str(session_id) in client.inventory['session_ids']
            pid = session_shim_pid(session_id)
            if index == 0:
                # No stream is attached; adoption must install the same watcher
                # as creation without depending on a terminal EOF or Close.
                client.kill()
                client.start()
                assert str(session_id) in client.inventory['session_ids']
                idle(client, 'unattached adopted shim', 1)
            before = time.perf_counter_ns()
            os.kill(pid, signal.SIGKILL)
            census(client, session_id, False, time.monotonic() + 0.4)
            latencies.append((time.perf_counter_ns() - before) / 1000)
        client.ping(168, 0)
        idle(client, 'all watched shims exited', 0)
        latencies.sort()
        print(f'event_exit_latency source=real-daemon-leg-B-census signal=SIGKILL '
              f'attached=false samples={samples} p50_us={latencies[int((samples-1)*.50)]:.0f} '
              f'p99_us={latencies[int((samples-1)*.99)]:.0f} max_us={max(latencies):.0f} '
              f'budget_us=400000 machine={os.uname().nodename} arch={os.uname().machine} '
              f'cores={os.cpu_count()} load={Path("/proc/loadavg").read_text().split()[:3]}', flush=True)
        assert max(latencies) <= 400000
    finally:
        if hasattr(client, 'child'):
            client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=100)
    args = parser.parse_args()
    assert args.samples > 0
    run(args.binary.resolve(), args.samples)
