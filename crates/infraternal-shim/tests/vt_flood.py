#!/usr/bin/env python3
"""Measure 50 MiB LF/CRLF/printable through real shim and infraternal agent [41]."""
import argparse
import os
from pathlib import Path
import struct
import sys
import time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path('scripts').resolve()))
from agent_fixture import Binary, cleanup, varint, rss

def run(binary):
    state=Path(f'target/vf{os.getpid()}');state.mkdir(mode=0o700)
    client=Binary(binary.resolve(),state)
    try:
        print(f'host release binary={binary}; pinned perf VM=no',flush=True)
        print(f'idle infraternal agent RSS={rss(client.child.pid)} KiB',flush=True)
        for label,pattern in [('LF',r'x\n'),('CRLF',r'x\r\n'),('printable','x')]:
            client.open();client.attach();client.until(b'shim-test');client.wait_ack()
            client.input(b"stty -echo -opost; printf 'VT_%s' READY\n");client.until(b'VT_READY');client.wait_ack();client.data.clear()
            # Exactly 1,600 reusable 32 KiB writes. CRLF padding makes the byte
            # count exact without leaving a partial control sequence per chunk.
            script=f'import os; p=b"{pattern}"; d=(p*(32768//len(p))).ljust(32768,b"x"); [os.write(1,d) for _ in range(1600)]'
            command=f"python3 -c '{script}'; printf 'VT_%s' DONE\n".encode()
            start=time.perf_counter();initial=client.out;client.input(command)
            # Credit every real mux output frame, retaining only a bounded
            # suffix for completion detection rather than buffering the flood.
            while b'VT_DONE' not in client.data:
                client.process()
                if len(client.data)>32768: del client.data[:-32768]
            elapsed=time.perf_counter()-start;count=client.out-initial
            assert count>=50*1024*1024
            print(f'{label}: bytes={count} seconds={elapsed:.6f} MB/s={count/elapsed/1e6:.3f} MiB/s={count/elapsed/1024/1024:.3f}',flush=True)
            client.wait_ack();client.send(1,0x0f,struct.pack('<H',0)+varint(4)+b'done')
    finally:
        client.kill();cleanup(state)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);args=p.parse_args();run(args.binary)
