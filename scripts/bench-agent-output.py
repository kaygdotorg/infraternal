#!/usr/bin/env python3
"""Compare binary relay workloads and credit batching without changing VT [5][41]."""
import argparse
import os
from pathlib import Path
import struct
import socket
import subprocess
import signal
import shutil
import sys
import time
sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, exact


def run(binary, runs, batched, credit_batch, workload, trace, enforce_budget, strace_binary):
    state = Path(f'target/tp{os.getpid()}')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    client.credit_batch = credit_batch
    credits = [0]
    send = client.send
    def counted_send(stream, kind, body=b''):
        if kind == 0x14:
            credits[0] += 1
        send(stream, kind, body)
    client.send = counted_send
    tracer = None
    try:
        client.open()
        with socket.socket(socket.AF_UNIX) as peer:
            peer.connect(str(state / "sessions" / (client.id.hex + ".sock")))
            hello = exact(peer, struct.unpack("<I", exact(peer, 4))[0])
            shim_pid = struct.unpack("<I", hello[27:31])[0]
        client.attach()
        client.until(b'shim-test')
        client.input(b"stty -echo -opost; printf 'START_%s' OK\n")
        client.until(b'START_OK')
        client.wait_ack()
        if trace:
            tracer = subprocess.Popen(['sudo', '-n', str(strace_binary or shutil.which('strace') or 'strace'), '-c', '-p', f'{client.child.pid},{shim_pid}', '-e', 'trace=read,write,sendto,recvfrom,poll,epoll_pwait,wait4', '-o', str(trace)], stderr=subprocess.DEVNULL)
            time.sleep(.1)
        for label, command in [('LF', 'yes | head -c 50M'),
                               ('CRLF', "yes $'y\\r' | head -c 50M"),
                               ('PRINTABLE', "yes | head -c 50M | tr '\\n' x")]:
            if workload and label != workload:
                continue
            for iteration in range(runs):
                credits[0] = 0
                if batched:
                    client.send(1, 0x14, struct.pack('<I', 64 * 1024 * 1024))
                client.data.clear()
                start = time.monotonic()
                client.input((command + "; printf 'END_%s' OK\n").encode())
                deadline = time.monotonic() + 120
                while b'END_OK' not in client.data[max(0, len(client.data) - 32768):]:
                    assert time.monotonic() < deadline
                    client.process(credit=not batched)
                elapsed = time.monotonic() - start
                client.wait_ack()
                print(f'{label} run={iteration} credit={"batched" if batched else str(credit_batch)} grants={credits[0]} bytes={len(client.data)} seconds={elapsed:.6f} MiB/s={len(client.data)/elapsed/1048576:.3f}', flush=True)
                if enforce_budget:
                    assert len(client.data) / elapsed >= 10_000_000, 'decision 41 output rate below 10 MB/s'
    finally:
        if tracer:
            tracer.send_signal(signal.SIGINT)
            tracer.wait()
            assert trace.is_file() and trace.stat().st_size > 0, 'syscall trace unavailable'
        if client.child.poll() is None:
            client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--batched', action='store_true')
    parser.add_argument('--credit-batch', type=int, default=1)
    parser.add_argument('--workload', choices=['LF', 'CRLF', 'PRINTABLE'])
    parser.add_argument('--trace', type=Path)
    parser.add_argument('--enforce-budget', action='store_true', help='require decision 41 throughput on the pinned performance VM')
    parser.add_argument('--strace', type=Path, help='optional tracing executable when not in PATH')
    args = parser.parse_args()
    run(args.binary, args.runs, args.batched, args.credit_batch, args.workload, args.trace, args.enforce_budget, args.strace)
