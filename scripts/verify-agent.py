#!/usr/bin/env python3
"""Real-binary leg-B abrupt-stop/restart, credit and release performance evidence [13][41]."""
import argparse
import sys

# Keep fixture imports from creating untracked bytecode in the worktree.
sys.dont_write_bytecode = True
import os
from pathlib import Path
import random
import select
import struct
import threading
import time

from agent_fixture import Binary, AckBarrier, cleanup, fixture_state, rss, varint
from idle_canary import assert_process_idle, session_shim_pid
from latency_proxy import LatencyConfig, percentile


def run(binary, state, functional=False, seed=20):
    state.mkdir(mode=0o700)
    client = Binary(binary, state)
    barrier = None
    peaks = []
    stopped = threading.Event()
    try:
        # Manager detection launches a one-shot child. Exclude its startup
        # reap from the steady-state canary, while retaining the >1s window
        # that detects periodic maintenance (no threshold is relaxed).
        time.sleep(0.25)
        idle = rss(client.child.pid)
        idle_agent = assert_process_idle(client.child.pid, 'idle infraternal agent')
        assert idle < 15 * 1024
        print(
            f'idle infraternal agent: {idle_agent.total_slices} scheduled slices over '
            f'{idle_agent.elapsed_seconds:.3f} s '
            f'({idle_agent.scheduled_per_minute:.3f}/min); RSS={idle} KiB',
            flush=True,
        )
        session = client.open()
        client.attach()
        client.until(b'shim-test')
        shim_pid = session_shim_pid(session)
        attached_agent = assert_process_idle(
            client.child.pid, 'idle infraternal agent with attached shim'
        )
        idle_shim = assert_process_idle(shim_pid, 'idle session shim')
        print(
            f'idle attached infraternal agent: {attached_agent.total_slices} scheduled slices '
            f'over {attached_agent.elapsed_seconds:.3f} s; '
            f'idle session shim: {idle_shim.total_slices} over '
            f'{idle_shim.elapsed_seconds:.3f} s',
            flush=True,
        )
        client.input(b"printf 'OPEN_%s\\n' OK\n")
        client.until(b'OPEN_OK\r\n')
        client.wait_ack()
        client.input(b'exit 7\n')
        terminal_exit = client.wait_event('terminal.exited')
        assert terminal_exit == dict(
            type='terminal.exited', session_id=str(session), status=7, final_seq=client.out
        )
        print('real terminal.open/type/output and terminal.exited status=7: PASS', flush=True)
        client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        client.open()
        barrier = AckBarrier(state, client.id)
        client.attach()
        client.until(b'shim-test')
        client.input(b"stty raw -echo; printf 'RAW_%s' READY; cat\n")
        client.until(b'RAW_READY')
        client.wait_ack()
        rng = random.Random(seed)
        positions = ['before-forward', 'after-send', 'mid-stream', 'PTY-write-before-Ack'] * 6
        rng.shuffle(positions)
        total = 0
        for iteration, position in enumerate(positions, 1):
            client.data.clear()
            payload = bytes(rng.randrange(32, 127) for _ in range(128)) * rng.randrange(1024, 4097)
            if position == 'PTY-write-before-Ack':
                # Keep below transport buffers while the caller waits for the
                # held Ack without reading output; otherwise the oracle itself
                # could deadlock the independently backpressured writer.
                payload = payload[:rng.randrange(512, 2049)]
            cursor = client.entered
            barrier.held.clear()
            barrier.release.clear()
            if position in ('before-forward', 'PTY-write-before-Ack'):
                # The same proxy can hold input before shim delivery, or hold
                # the real PTY-write Ack before the daemon receives it. These
                # are event barriers, independent of scheduling or sleep timing.
                barrier.kind = 0x17 if position == 'before-forward' else 0x18
                barrier.threshold = cursor if position == 'before-forward' else cursor + len(payload)
            client.input(payload)
            if position in ('before-forward', 'PTY-write-before-Ack'):
                assert barrier.held.wait(20), f'never reached {position} barrier'
            elif position == 'mid-stream':
                threshold = rng.randrange(1, len(payload) // 2)
                while len(client.data) < threshold:
                    client.process()
                assert 0 < len(client.data) < len(payload), 'abrupt stop must interrupt output'
            observed = len(client.data)
            client.kill()
            barrier.release.set()
            client.start()
            client.attach()
            # Deliberately replay the whole submitted range, including overlap
            # with accepted/written bytes: only the surviving shim owns truth.
            client.send(1, 0x10, struct.pack('<Q', cursor) + payload)
            fence = f'<REPLAY_FENCE_{iteration:02d}>'.encode()
            client.input(fence)
            try:
                # Attach funds 1MiB, more than this <=512KiB replay and fence.
                # Refunding this burst adds commands behind the replay and can
                # retire a valid stream at its eight-command admission bound.
                # Each next restart attaches with its own fresh funded window.
                while len(client.data) < len(payload) + len(fence) or client.acked < client.entered:
                    client.process(credit=False)
            except Exception:
                print(f'restart oracle stalled: iteration={iteration}, position={position}, payload={len(payload)}, observed={observed}, received={len(client.data)}, input sent={client.entered}, input acked={client.acked}, output cursor={client.out}, proxy alive={barrier.thread.is_alive()}, proxy threshold={barrier.threshold}, proxy phase={barrier.phase}', flush=True)
                raise
            assert client.data == payload + fence, (iteration, position, len(client.data))
            total += len(payload)
            print(f'abrupt stop/restart {iteration:02d}/24 {position}: {len(payload)} bytes, output observed before stop={observed}; exact input/output replay: PASS', flush=True)
        print(f'24-iteration restart fixture seed={seed}: {total} payload bytes, all four stop positions x 6: PASS', flush=True)
        if functional:
            return
        # The proxy is a correctness fixture; latency and flood use a new direct session.
        client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        barrier.close()
        barrier = None
        client.open()
        client.attach()
        client.until(b'shim-test')
        client.input(b"stty raw -echo; printf 'BENCH_%s' READY; cat\n")
        client.until(b'BENCH_READY')
        client.wait_ack()
        samples = []
        client.data.clear()
        for _ in range(1000):
            before = time.perf_counter_ns()
            client.input(b'x')
            client.wait_ack()
            samples.append((time.perf_counter_ns() - before) / 1000)
        samples.sort()
        rtt_config = LatencyConfig.from_environment()
        echo_budget_ms = rtt_config.rtt_ms + 34
        p50_ms = percentile(samples, 0.50) / 1000
        p99_ms = percentile(samples, 0.99) / 1000
        print(
            f'METRIC name=keystroke_echo_confirmed_native source=real-agent-pty n={len(samples)} '
            f'p50_ms={p50_ms:.2f} p99_ms={p99_ms:.2f} budget_ms={echo_budget_ms:.2f} '
            f'result={"PASS" if p99_ms <= echo_budget_ms else "FAIL"}',
            flush=True,
        )
        assert p99_ms <= echo_budget_ms, f'Input-to-PTY Ack exceeded RTT + 2 frames ({echo_budget_ms:.2f} ms)'
        client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        client.open()
        client.attach()
        client.until(b'shim-test')
        client.input(b"stty -echo -opost; printf 'FLOOD_%s' READY\n")
        client.until(b'FLOOD_READY')
        client.wait_ack()
        client.data.clear()
        start = time.monotonic()
        client.input(b"yes | head -c 50M; printf 'FLOOD_%s' DONE\n")
        client.until(b'FLOOD_DONE')
        elapsed = time.monotonic() - start
        count = len(client.data)
        assert count >= 50 * 1024 * 1024
        print(f'credited flood: {count} bytes in {elapsed:.3f} s, {count/elapsed/1024/1024:.3f} MiB/s', flush=True)
        client.wait_ack()
        client.data.clear()
        before = client.out
        def measure():
            while not stopped.wait(.01):
                peaks.append(rss(client.child.pid))
        sampler = threading.Thread(target=measure)
        sampler.start()
        marker = state.resolve() / "starved"
        client.input(f"yes | head -c 50M; printf 'STARVE_%s' DONE; : > '{marker}'\n".encode())
        # Drain the remaining initial credit without granting more. The fixture
        # completion file proves the entire flood progressed while detached.
        while select.select([client.sock], [], [], .5)[0]:
            client.process(credit=False)
        deadline = time.monotonic() + 30
        while not marker.exists():
            assert time.monotonic() < deadline, 'detached flood did not finish'
            time.sleep(.01)
        client.send(1, 0x14, struct.pack('<I', 1024 * 1024))
        while not client.snapshots:
            client.process(credit=False)
        seq, size = client.snapshots[-1]
        stopped.set()
        sampler.join()
        # The shell completion file proves it wrote 50 MiB; the final kernel
        # PTY buffer can still be unread when Snapshot captures shim state.
        # That suffix must arrive contiguously after the snapshot, never vanish.
        assert seq > before + 49 * 1024 * 1024, (seq, before)
        while client.out < before + 50 * 1024 * 1024:
            client.process(credit=False)
        assert max(peaks) < 15 * 1024
        print(f'starved 50 MiB: Snapshot seq={seq}, repaint={size} bytes; final cursor={client.out}; daemon peak RSS={max(peaks)} KiB; no retained flood', flush=True)
    finally:
        stopped.set()
        if barrier:
            barrier.close()
        if client.child.poll() is None:
            client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=Path(os.environ.get('CARGO_TARGET_DIR', 'target')) / 'x86_64-unknown-linux-musl/release/infraternal')
    parser.add_argument("--functional", action="store_true", help="run short real-process correctness gates without release measurements")
    parser.add_argument("--seed", type=int, default=20, help="reproducible stop positions and payload sizes")
    args = parser.parse_args()
    run(args.binary.resolve(), fixture_state('tb'), args.functional, args.seed)
