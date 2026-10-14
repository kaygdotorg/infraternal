#!/usr/bin/env python3
"""Measure fixture-owned shim hosts on the locked perf VM; never sample unrelated processes."""
import argparse
import hashlib
import json
import os
import resource
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import time


def send(peer, kind, payload=b''):
    peer.sendall(struct.pack('<I', len(payload) + 1) + bytes([kind]) + payload)


def exact(peer, count):
    data = bytearray()
    while len(data) < count:
        part = peer.recv(count - len(data))
        if not part:
            raise EOFError('fixture peer closed')
        data.extend(part)
    return bytes(data)


def frame(peer):
    size = struct.unpack('<I', exact(peer, 4))[0]
    if size > 1024 * 1024:
        raise ValueError('oversized frame')
    return exact(peer, size)


def echoed(tail, data, marker):
    """Recognize real shell printf output while carrying a fragmented marker."""
    combined = tail + data
    needle = marker + b'\r\n'
    return needle in combined, combined[-(len(needle)-1):]


def birth(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_bytes().rsplit(b') ', 1)[1].split()[19]
    except FileNotFoundError:
        return None


def memory(pid):
    values = {}
    for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines()[1:]:
        key, _, value = line.partition(':')
        if key in ('Rss', 'Pss', 'Anonymous', 'Private_Dirty'):
            values[key] = int(value.split()[0])
    return values


def optional_memory(pid):
    try:
        return memory(pid)['Pss']
    except (FileNotFoundError, ProcessLookupError):
        return 0


def cpu(pid):
    values = Path(f'/proc/{pid}/stat').read_bytes().rsplit(b') ', 1)[1].split()
    return int(values[11]) + int(values[12])


def switches(pid):
    return sum(int(line.split(':')[1]) for line in Path(f'/proc/{pid}/status').read_text().splitlines()
               if line.startswith(('voluntary_ctxt_switches:', 'nonvoluntary_ctxt_switches:')))


def percentiles(values):
    values.sort()
    return dict(samples=len(values), p50_ms=values[len(values)//2], p99_ms=values[min(len(values)-1, int(len(values)*.99))], max_ms=values[-1])


def emit(**values):
    print(json.dumps(dict(load=Path('/proc/loadavg').read_text().strip(), **values)), flush=True)


def run(args):
    root = Path(args.state)
    root.mkdir(mode=0o700)
    children, shells = [], {}
    peers = []
    origin = int.from_bytes(os.urandom(16), 'big')
    ids = [f'{(origin + i) % (1 << 128):032x}' for i in range(args.sessions)]
    host_pids = []
    sustained = args.mode == "host" or args.sessions < 1000 or args.sustained_baseline
    def connect(index):
        peer = socket.socket(socket.AF_UNIX)
        peer.settimeout(30)
        peer.connect(str(root/'sessions'/f'{ids[index]}.sock'))
        hello = frame(peer)
        assert hello[0] == 1
        return peer, hello
    def heads():
        total = 0
        for i in range(args.sessions):
            peer, hello = connect(i)
            total += struct.unpack('<Q', hello[43:51])[0]
            peer.close()
        return total
    def sample(phase):
        values = [memory(pid) for pid in host_pids]
        total = {key: sum(value[key] for value in values) for key in values[0]}
        shell_total = sum(memory(pid)['Pss'] for pid in shells if birth(pid) == shells[pid])
        emit(phase=phase, mode=args.mode, n=args.sessions, hosts=len(host_pids),
             total_kib=total, per_session_kib={key: val/args.sessions for key, val in total.items()},
             shell_pss_kib=shell_total,
             workload_children_pss_kib=sum(optional_memory(int(child)) for pid in shells if birth(pid)==shells[pid]
                 for child in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
                 if Path(f'/proc/{child}/smaps_rollup').exists()), threads=sum(len(list(Path(f'/proc/{pid}/task').iterdir())) for pid in host_pids))
    def latency(phase, samples):
        # Attach and echo samples use the same session and real account shell.
        # ReadFrom(head) is explicitly established before each measured input.
        hello_times, snapshots, echoes = [], [], []
        approximate = 0
        for _ in range(samples):
            started = time.monotonic()
            peer, hello = connect(0)
            hello_times.append((time.monotonic()-started)*1000)
            send(peer, 2, struct.pack('<Q',4))
            started = time.monotonic()
            send(peer, 0x14)
            snapshot = frame(peer)
            assert snapshot[0] in (0x15, 0x1c), "snapshot request returned an error"
            approximate += int(snapshot[0] == 0x1c and snapshot[9] & 1 != 0)
            snapshots.append((time.monotonic()-started)*1000)
            peer.close()
        peer, hello = connect(0)
        peers.append(peer)
        send(peer,2,struct.pack('<Q',0))
        send(peer,0x13,hello[43:51])
        for i in range(samples):
            marker = f'ECHO_{i:08x}'.encode()
            started = time.monotonic()
            # A printf format creates the marker only in output, never in the
            # echoed command line, so command echo cannot satisfy the sample.
            send(peer,0x10,b"printf 'ECHO_%08x\\n' "+str(i).encode()+b'\n')
            tail=b''
            while marker+b'\r\n' not in tail:
                data=frame(peer)
                assert data[0]==0x11, data[0]
                matched, tail = echoed(tail, data[9:], marker)
                if matched: break
            echoes.append((time.monotonic()-started)*1000)
        emit(phase=phase+'-latency', mode=args.mode, n=args.sessions, hello=percentiles(hello_times),
             snapshot=percentiles(snapshots), approximate_snapshots=approximate, echo=percentiles(echoes), measured_while_flooding=phase=="flood" and sustained)
        peer.close()
        peers.remove(peer)
    try:
        binary = str(Path(args.binary).resolve())
        emit(phase='environment', profile=args.profile, mode=args.mode, machine=os.uname().nodename, kernel=os.uname().release,
             cpu_count=os.cpu_count(), cpu_model=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'), nofile=resource.getrlimit(resource.RLIMIT_NOFILE), binary_sha256=hashlib.file_digest(open(binary,'rb'),'sha256').hexdigest(),
             binary_bytes=Path(binary).stat().st_size, dimensions='80x24', n=args.sessions)
        for i in range(1 if args.mode == 'host' else args.sessions):
            command = [binary,'__shim','--session',ids[i],'--uid',str(os.getuid()),'--state',str(root)]
            if args.mode == 'host': command += ['--host-sessions',str(args.sessions)]
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            children.append(child)
            host_pids.append(child.pid)
        until = time.monotonic() + 120
        for i in range(args.sessions):
            while True:
                try:
                    peer, _ = connect(i)
                    peer.close()
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    assert time.monotonic() < until, ('startup', i)
                    time.sleep(.01)
        for pid in host_pids:
            for child in Path(f'/proc/{pid}/task/{pid}/children').read_text().split():
                shell = int(child)
                shells[shell] = birth(shell)
        assert len(shells) == args.sessions
        emit(phase="fixture-pids", host_pids=host_pids, shell_pids=list(shells))
        time.sleep(1)
        sample('idle')
        before_cpu = sum(cpu(pid) for pid in host_pids)
        before_switch = sum(switches(pid) for pid in host_pids)
        started = time.monotonic()
        time.sleep(5)
        emit(phase='idle-cpu', n=args.sessions, mode=args.mode, seconds=time.monotonic()-started,
             cpu_ticks=sum(cpu(pid) for pid in host_pids)-before_cpu,
             context_switches=sum(switches(pid) for pid in host_pids)-before_switch, tick_hz=os.sysconf('SC_CLK_TCK'))
        if args.profile == "latency": latency("idle", args.samples)
        light_cpu = sum(cpu(pid) for pid in host_pids)
        light_start = time.monotonic()
        # Light output: one 32-character line per session per second for five seconds.
        # Close each control link immediately so no viewer stalls the output pump.
        for _ in range(5):
            for i in range(args.sessions):
                peer, _ = connect(i)
                send(peer, 2, struct.pack('<Q',0))
                send(peer, 0x10, b"printf 'light-output-0123456789abcdef\\n'\n")
                peer.close()
            time.sleep(1)
        emit(phase='light-cpu', mode=args.mode, n=args.sessions,
             cpu_ticks=sum(cpu(pid) for pid in host_pids)-light_cpu, seconds=time.monotonic()-light_start)
        sample('light')
        if args.profile == "latency": latency("light", args.samples)
        # Every PTY floods, but only for this bounded burst. Baseline gets a
        # finite per-session byte count to avoid exhausting the shared 7-GiB VM.
        flood_origin = heads()
        flood_cpu = sum(cpu(pid) for pid in host_pids)
        flood_start = time.monotonic()
        flood_bytes = 32768 if args.sessions >= 1000 else 262144
        for i in range(args.sessions):
            peer, _ = connect(i)
            send(peer, 2, struct.pack('<Q',0))
            command = (f"head -c {flood_bytes}".encode()+b" /dev/zero | tr '\\000' 'x'; printf '\\n'\n" if not sustained
                       else b"yes 'flood-output-0123456789abcdef' & flood_pid=$!\n")
            send(peer, 0x10, command)
            peer.close()
        time.sleep(10)
        flood_output = heads() - flood_origin
        emit(phase='flood-cpu', mode=args.mode, n=args.sessions, output_bytes=flood_output,
             cpu_ticks=sum(cpu(pid) for pid in host_pids)-flood_cpu, seconds=time.monotonic()-flood_start)
        emit(phase='flood-workload', mode=args.mode, n=args.sessions, sustained=sustained, bounded_bytes_per_session=None if sustained else flood_bytes)
        sample('flood')
        # Capture a short sample while the other PTYs still flood; scope timeout
        # caps the whole run and guarantees the two-minute burst ceiling.
        latency("flood", min(args.samples, 3 if args.sessions >= 1000 else 31))
        for i in range(args.sessions):
            peer, _ = connect(i)
            send(peer, 2, struct.pack('<Q',0))
            if sustained:
                send(peer, 0x10, b'kill "$flood_pid"; wait "$flood_pid" 2>/dev/null; unset flood_pid\n')
            else:
                send(peer, 0x16, bytes([signal.SIGINT]))
            peer.close()
        time.sleep(1)
        latency("settled", args.samples)
    finally:
        # A wrapper may forward the same interrupt twice. Finish fixture-owned
        # cleanup atomically instead of leaving output generators behind.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for peer in peers: peer.close()
        # Sessions may have started after an interrupted startup: discover only
        # immediate children of our own still-live fixture hosts before cleanup.
        for child in children:
            if child.poll() is None:
                try:
                    for pid in Path(f'/proc/{child.pid}/task/{child.pid}/children').read_text().split():
                        shell=int(pid); shells.setdefault(shell,birth(shell))
                except FileNotFoundError: pass
        for pid, born in shells.items():
            if born is not None and birth(pid)==born:
                try: os.killpg(pid,signal.SIGKILL)
                except ProcessLookupError: pass
        for child in children:
            if child.poll() is None: child.kill()
            child.wait()
        shutil.rmtree(root)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    parser.add_argument('--state',required=True)
    parser.add_argument('--mode',choices=['host','baseline'],required=True)
    parser.add_argument('--sessions',type=int,required=True)
    parser.add_argument('--samples',type=int,default=1000)
    parser.add_argument('--profile',choices=['memory','latency'],default='memory')
    parser.add_argument('--sustained-baseline',action='store_true',help='sustained 1000-session baseline; run inside an OOM-group memory scope')
    args = parser.parse_args()
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE,(min(16384,hard),hard))
    run(args)
