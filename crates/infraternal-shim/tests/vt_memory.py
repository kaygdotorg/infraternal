#!/usr/bin/env python3
"""Measure real static shim RSS idle/full and snapshot latency at 200x60 [41]."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time
import uuid

def rss(pid):
    return next(int(line.split()[1]) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if line.startswith('VmRSS:'))
def exact(sock,n):
    out=bytearray()
    while len(out)<n:
        part=sock.recv(n-len(out)); assert part;out.extend(part)
    return bytes(out)
def read(sock):
    n=struct.unpack('<I',exact(sock,4))[0];assert 0<n<=1048576
    body=exact(sock,n);return body[0],body[1:]
def send(sock,kind,body=b''):
    sock.sendall(struct.pack('<I',len(body)+1)+bytes([kind])+body)
def run(binary):
    state=Path(f'target/vr{os.getpid()}');session=uuid.uuid4().hex
    env=dict(os.environ,ZDOTDIR=str(Path('crates/infraternal/tests/profile').resolve()))
    child=subprocess.Popen([str(binary.resolve()),'__shim','--session',session,'--uid',str(os.getuid()),'--state',str(state),'--cols','200','--rows','60'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    peer=socket.socket(socket.AF_UNIX);peer.settimeout(30)
    try:
        path=state/'sessions'/f'{session}.sock';deadline=time.monotonic()+10
        while not path.exists(): assert time.monotonic()<deadline;time.sleep(.01)
        peer.connect(str(path));kind,hello=read(peer);assert kind==1
        send(peer,2,struct.pack('<Q',0));send(peer,0x13,struct.pack('<Q',0))
        tail=bytearray()
        while b'shim-test' not in tail:
            kind,body=read(peer);assert kind==0x11;tail.extend(body[8:]);del tail[:-1024]
        time.sleep(.2);idle=rss(child.pid)
        script=r'import os; d=b"1234567890 abcdefghijklmnopqrstuvwxyz\r\n"*8192; n=50*1024*1024; done=0; exec("while done<n:\n done+=os.write(1,d[:min(len(d),n-done)])")'
        command=f"stty -echo -opost; python3 -c '{script}'; printf 'MEM_%s' DONE\n".encode()
        send(peer,0x10,command);tail.clear()
        while b'MEM_DONE' not in tail:
            kind,body=read(peer);assert kind==0x11;tail.extend(body[8:]);del tail[:-1024]
        # The flood fills both native history and the lazy 8 MiB output ring.
        time.sleep(.2);full=rss(child.pid)
        print(f'static shim 200x60: idle_RSS_KiB={idle} full_scrollback_and_8MiB_ring_RSS_KiB={full}',flush=True)
        # Include request framing, allocation, serialization, socket delivery
        # and decode. This is deliberately wider than the Rust serializer timer.
        times=[];size=0
        for _ in range(1000):
            start=time.perf_counter_ns();send(peer,0x14)
            while True:
                kind,body=read(peer)
                if kind==0x15: break
                assert kind==0x11
            times.append((time.perf_counter_ns()-start)/1e6);size=len(body)-8
        times.sort()
        print(f'static shim socket snapshot 200x60: n=1000 p50_ms={times[500]:.3f} p99_ms={times[990]:.3f} bytes={size}',flush=True)
    finally:
        peer.close();child.kill();child.wait();child.stderr.close();shutil.rmtree(state,ignore_errors=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);args=p.parse_args();run(args.binary)
