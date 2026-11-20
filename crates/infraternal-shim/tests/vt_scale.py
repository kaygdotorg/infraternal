#!/usr/bin/env python3
"""Measure full-history socket snapshots across the 128-session registry limit [41]."""
import argparse, os, socket, struct, sys, time
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path('scripts').resolve()))
from agent_fixture import Binary, cleanup, exact, rss


def read(peer):
    length=struct.unpack('<I',exact(peer,4))[0]
    assert 0 < length <= 1024*1024, 'bounded shim response'
    body=exact(peer,length)
    return body[0],body[1:]


def send(peer,kind,body=b''):
    peer.sendall(struct.pack('<I',len(body)+1)+bytes([kind])+body)


def summarize_rss(session_pids, baseline_by_pid, current_by_pid):
    """Summarize per-session RSS without counting a shared owner twice."""
    owners = set(session_pids)
    total_rss = sum(current_by_pid[pid] for pid in owners)
    growth = sum(current_by_pid[pid] - baseline_by_pid[pid] for pid in owners)
    growth_per_session = growth / len(session_pids) if session_pids else 0.0
    return len(owners), total_rss, growth, growth_per_session


def run(binary,count,memory_only=False):
    """Measure RSS and snapshots; memory-only mode skips the snapshot work."""
    state=Path(f'target/vt-scale-{os.getpid()}');state.mkdir(mode=0o700)
    c=Binary(binary.resolve(),state); peers=[]; pids=[]; ids=[]; baseline_by_pid={}
    print(f'scale start: sessions={count} CPUs={os.cpu_count()} load={os.getloadavg()}',flush=True)
    try:
        for _ in range(count):
            c.open(cols=200,rows=60); identity=c.id;ids.append(identity)
            c.attach();c.until(b'shim-test');c.wait_ack()
            c.send(1,0x0f,struct.pack('<H',0)+b'scale detach')
            # Local requests use the real shim, avoiding a benchmark-only engine.
            peer=socket.socket(socket.AF_UNIX);peer.settimeout(30)
            peer.connect(str(state/'sessions'/(identity.hex+'.sock')))
            kind,hello=read(peer);assert kind==1
            pid=struct.unpack('<I',hello[26:30])[0]
            pids.append(pid)
            if pid not in baseline_by_pid:
                baseline_by_pid[pid]=rss(pid)
            send(peer,2,struct.pack('<Q',0));send(peer,0x13,struct.pack('<Q',0))
            # Existing output can precede the setup marker; only printable
            # benchmark summaries leave the fixture socket.
            command=b"stty -echo -opost; printf '\\033c'; python3 -c 'import sys; sys.stdout.buffer.write(b\"1234567890 abcdefghijklmnopqrstuvwxyz\\r\\n\"*(9*1024*1024//37+1))'; printf 'SCALE_%s' READY\n"
            send(peer,0x10,command)
            tail=bytearray()
            while b'SCALE_READY' not in tail:
                kind,body=read(peer);assert kind==0x11,'setup must remain raw';tail.extend(body[8:]);del tail[:-1024]
            peers.append(peer)
        time.sleep(.1)
        owners=set(pids)
        current_by_pid={pid:rss(pid) for pid in owners}
        owner_count,total_rss,rss_growth,growth_per_session=summarize_rss(pids,baseline_by_pid,current_by_pid)
        proportional=[next(int(line.split()[1]) for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines() if line.startswith('Pss:')) for pid in owners]
        print(f'scale full 200x60/history+8MiB ring: sessions={count} owners={owner_count} shim_RSS_sum_KiB={total_rss} shim_RSS_growth_KiB={rss_growth} shim_RSS_growth_per_session_KiB={growth_per_session:.1f} shim_PSS_sum_KiB={sum(proportional)} daemon_RSS_KiB={rss(c.child.pid)} load={os.getloadavg()}',flush=True)
        if memory_only:
            return
        serial=[];sizes=[]
        for peer in peers:
            start=time.perf_counter_ns();send(peer,0x14)
            while True:
                kind,body=read(peer)
                if kind==0x15:break
                assert kind==0x11,'faithful full-history fixture must remain representable'
            serial.append((time.perf_counter_ns()-start)/1e6);sizes.append(len(body)-8)
        serial.sort()
        print(f'scale serial socket snapshots: n={count} p50_ms={serial[count//2]:.3f} p99_ms={serial[min(count-1,int(count*.99))]:.3f} bytes_min={min(sizes)} max={max(sizes)}',flush=True)
        burst=[]
        for _ in range(10):
            start=time.perf_counter_ns()
            for peer in peers:send(peer,0x14)
            for peer in peers:
                kind,_=read(peer);assert kind==0x15,'burst must return faithful snapshots'
                burst.append((time.perf_counter_ns()-start)/1e6)
        burst.sort()
        p99=burst[int(len(burst)*.99)]
        print(f'scale simultaneous socket recovery: sessions={count} samples={len(burst)} p99_ms={p99:.3f} max_ms={max(burst):.3f} load={os.getloadavg()}',flush=True)
        assert p99<300,'128-session reconnect burst exceeds decision 41 300ms budget'
    finally:
        for peer in peers:peer.close()
        c.kill();cleanup(state)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--sessions',type=int,default=128);p.add_argument('--memory-only',action='store_true')
    a=p.parse_args();run(a.binary,a.sessions,a.memory_only)
