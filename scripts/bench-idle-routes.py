#!/usr/bin/env python3
"""Measure real shipping PTYs and browser route proofs on the locked perf VM [81,265], #199.

The private fixture persists only a hash of its in-memory browser capability.
Scheduler activations are schedule-ins (schedstat field three), not hardware interrupts.
The default profile sends the browser’s 25 ms probes in both directions;
responses-only remains available to identify the earlier incomplete fixture.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import time
import uuid

from agent_fixture import varint


def integer(data, offset=0):
    """Decode the fixture's bounded mux header, never diagnostic payloads."""
    value = 0
    for shift in range(0, 35, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError('invalid fixture varint')


class Browser:
    """Continuously poll one real WebSocket, including while sibling sessions open."""
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.queue = asyncio.Queue(4096)
        self.task = asyncio.create_task(self.receive())
        self.probe_task = None
        self.pending = {}
        self.probe_pongs = 0
        self.last_pong = time.monotonic()
        self.rtt = None
        self.last_ping = float('-inf')
        self.next_nonce = 1 << 63

    def start_probes(self):
        """Match the shared browser connection cadence and correlated proof deadline."""
        self.last_pong = time.monotonic()
        self.probe_task = asyncio.create_task(self.probe())

    async def sample_probe(self):
        """Share one cadence between timer callbacks and incoming server probes."""
        now = time.monotonic()
        if now - self.last_ping < .025:
            return
        # Publish the sample before yielding: receive and timer must not double-send.
        self.last_ping = now
        nonce = self.next_nonce
        self.next_nonce += 1
        if len(self.pending) >= 128:
            del self.pending[next(iter(self.pending))]
        sent = round(now * 1_000_000)
        self.pending[nonce] = (sent, now)
        await self.send(0, 8, struct.pack('<QQ', nonce, sent))

    async def probe(self):
        # The browser's first timer fires one tick after Welcome.
        await asyncio.sleep(.025)
        while True:
            now = time.monotonic()
            grace = 2 if self.rtt is None else self.rtt + .05
            assert now - self.last_pong < grace, 'fixture client proof expired'
            await self.sample_probe()
            clock = time.monotonic()
            grace = 2 if self.rtt is None else self.rtt + .05
            next_probe = self.last_ping + .025 - clock
            remaining = self.last_pong + grace - clock
            await asyncio.sleep(max(.001, min(next_probe, remaining)))

    async def send(self, stream, kind, body=b''):
        wire = bytes(varint(stream) + varint(len(body) + 1)) + bytes([kind]) + body
        await self.transport(2, wire)

    async def transport(self, opcode, wire):
        # Client frames must be masked; authority never appears in a receipt.
        mask = os.urandom(4)
        length = len(wire)
        header = bytes([0x80 | opcode])
        if length < 126:
            header += bytes([0x80 | length])
        elif length < 65536:
            header += b'\xfe' + struct.pack('!H', length)
        else:
            header += b'\xff' + struct.pack('!Q', length)
        self.writer.write(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(wire)))
        await self.writer.drain()

    async def receive(self):
        try:
            while True:
                header = await self.reader.readexactly(2)
                opcode, length = header[0] & 15, header[1] & 127
                if length == 126:
                    length = struct.unpack('!H', await self.reader.readexactly(2))[0]
                elif length == 127:
                    length = struct.unpack('!Q', await self.reader.readexactly(8))[0]
                assert length <= 2 * 1024 * 1024, 'fixture frame bound'
                wire = await self.reader.readexactly(length)
                if opcode == 9:
                    await self.transport(10, wire)
                elif opcode == 2:
                    offset = 0
                    while offset < len(wire):
                        stream, offset = integer(wire, offset)
                        length, offset = integer(wire, offset)
                        kind, body = wire[offset], wire[offset + 1:offset + length]
                        offset += length
                        if kind == 8:
                            await self.send(stream, 9, body)
                            if self.probe_task is not None:
                                await self.sample_probe()
                        elif kind == 9 and stream == 0 and len(body) == 16 and struct.unpack('<Q', body[:8])[0] >= 1 << 63:
                            nonce, sent = struct.unpack('<QQ', body)
                            pending = self.pending.get(nonce)
                            if pending is not None and pending[0] == sent:
                                now = time.monotonic()
                                grace = 2 if self.rtt is None else self.rtt + .05
                                assert now - self.last_pong < grace, 'fixture late client proof'
                                self.rtt = max(.001, now - pending[1], (self.rtt or 0) * .95)
                                self.last_pong = now
                                self.probe_pongs += 1
                                self.pending = {key: value for key, value in self.pending.items() if key > nonce}
                        else:
                            self.queue.put_nowait((stream, kind, body))
                elif opcode == 8:
                    code = struct.unpack('!H', wire[:2])[0] if len(wire) >= 2 else None
                    print(json.dumps(dict(phase='browser_close', code=code)), flush=True)
                    raise EOFError('fixture browser closed')
        except (EOFError, asyncio.IncompleteReadError):
            self.queue.put_nowait(None)

    async def read(self):
        message = await asyncio.wait_for(self.queue.get(), 20)
        assert message is not None, 'fixture browser retired'
        return message

    async def close(self):
        tasks = [self.task] + ([self.probe_task] if self.probe_task else [])
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.writer.close()
        await self.writer.wait_closed()

    @classmethod
    async def connect(cls, port, token):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        key = base64.b64encode(os.urandom(16)).decode()
        writer.write((f'GET /v1/ws HTTP/1.1\r\nHost: localhost\r\n'
                      f'Origin: https://localhost\r\nCookie: __Host-infraternal={token}\r\n'
                      f'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                      f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        await writer.drain()
        response = await reader.readuntil(b'\r\n\r\n')
        assert response.startswith(b'HTTP/1.1 101'), 'fixture upgrade refused'
        browser = cls(reader, writer)
        assert (await browser.read())[1] == 0
        info = b'idle-fixture'
        await browser.send(0, 0, struct.pack('<HQ', 1, 0) + varint(len(info)) + info)
        assert (await browser.read())[1] == 1
        return browser


def snapshot(pid):
    """Read per-thread runtime and schedule-ins without waking the target."""
    return {int(task.name): tuple(map(int, (task / 'schedstat').read_text().split()))
            for task in Path(f'/proc/{pid}/task').iterdir()}


def shim_pids(runtime):
    """Identify only the fixture's private Unix peers; shims can own separate scopes."""
    pids = []
    sessions = runtime / 'infraternal/sessions'
    try:
        directory = os.open(sessions, os.O_RDONLY | os.O_DIRECTORY)
    except FileNotFoundError:
        return pids
    try:
        for path in sessions.glob('*.sock'):
            with socket.socket(socket.AF_UNIX) as peer:
                try:
                    # Keep the address below sun_path's limit without changing
                    # process cwd or following a fixture-wide runtime alias.
                    peer.connect(f'/proc/self/fd/{directory}/{path.name}')
                except (FileNotFoundError, ConnectionRefusedError):
                    continue
                pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                assert uid == os.getuid() and pid > 0, 'fixture peer ownership'
                pids.append(pid)
    finally:
        os.close(directory)
    return sorted(pids)


async def measure(pid, seconds):
    before = snapshot(pid)
    load = os.getloadavg()
    started = time.monotonic()
    await asyncio.sleep(seconds)
    elapsed = time.monotonic() - started
    after = snapshot(pid)
    # An exited worker would silently lose its CPU; churn invalidates this sample.
    assert before.keys() == after.keys(), 'fixture thread set changed during sample'
    threads = {tid: {'cpu_ns': values[0] - before[tid][0],
                     'schedule_ins': values[2] - before[tid][2],
                     'name': Path(f'/proc/{pid}/task/{tid}/comm').read_text().strip()}
               for tid, values in after.items()}
    return dict(seconds=elapsed, cpu_percent_one_core=sum(v['cpu_ns'] for v in threads.values()) / elapsed / 1e7,
                schedule_ins_per_second=sum(v['schedule_ins'] for v in threads.values()) / elapsed,
                threads=threads, load_before=load, load_after=os.getloadavg())


async def run(args):
    root = args.root.resolve()
    assert str(root).startswith('/root/infraternal-bench/idle-cpu-199/'), 'perf VM fixture only'
    root.mkdir(parents=True, mode=0o700)
    runtime = root / 'r'
    runtime.mkdir(mode=0o700)
    profile = root / 'profile'
    profile.mkdir(mode=0o700)
    (profile / '.zshrc').write_text("# Private quiet PTY fixture.\nPS1='idle% '\n")
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    unit = 'infraternal-idle-199-' + uuid.uuid4().hex
    browsers = []
    server_pid = None
    try:
        subprocess.run(['systemd-run', '--quiet', '--collect', '--unit', unit,
                        '-p', 'KillMode=control-group', '-p', 'StandardOutput=null', '-p', 'StandardError=null',
                        '-p', f'BindPaths={runtime}:/run', f'--setenv=ZDOTDIR={profile}',
                        str(args.binary.resolve()), 'server', '--listen', f'127.0.0.1:{port}',
                        '--data', str(root / 'data'), '--public-origin', 'https://localhost',
                        '--behind-proxy', '--trusted-proxy', '127.0.0.1'], check=True)
        for _ in range(600):
            if (root / 'data/setup-token.sock').exists():
                break
            await asyncio.sleep(.05)
        else:
            raise RuntimeError('fixture startup failed')
        server_pid = int(subprocess.check_output(['systemctl', 'show', unit, '-p', 'MainPID', '--value']))
        token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        digest = base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode().rstrip('=')
        with sqlite3.connect(root / 'data/infraternal.sqlite') as db:
            db.execute("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES('idle-owner','Idle','root','Idle',1,'unused')")
            db.execute("INSERT INTO passkeys(id,user_id,credential) VALUES('fixture-key','idle-owner','{}')")
            db.execute("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked,passkey_id) VALUES(?,'idle-owner','fixture',unixepoch()+3600,unixepoch(),1,'fixture-key')", (digest,))
        creator = await Browser.connect(port, token)
        browsers.append(creator)
        sessions = []
        for call in range(1, args.sessions + 1):
            action = b'terminal.open'
            await creator.send(0, 0x30, struct.pack('<I', call) + varint(len(action)) + action +
                               b'{"cols":80,"rows":24,"px_w":0,"px_h":0}')
            while True:
                _, kind, body = await creator.read()
                if kind == 0x31:
                    assert body[4] == 1, f'PTY open refused at {call}'
                    sessions.append(uuid.UUID(json.loads(body[5:])['session_id']))
                    break
                assert kind != 0x0f, 'fixture protocol close'
            if call % 32 == 0:
                print(json.dumps(dict(phase='create', revision=args.revision, real_ptys=call)), flush=True)
            await asyncio.sleep(.01)
        await creator.close()
        browsers.clear()
        pids = shim_pids(runtime)
        assert len(pids) == args.sessions, 'real shim count'
        for index in range(args.clients):
            browser = await Browser.connect(port, token)
            browsers.append(browser)
            if not args.responses_only:
                browser.start_probes()
            # Match the staging helper's 25-terminal chunks. Both specified
            # revisions admit at most 32 streams per browser socket.
            for offset, session in enumerate(sessions[index * 25:(index + 1) * 25]):
                stream = 2 * offset + 1
                await browser.send(stream, 0x16, session.bytes + bytes(16))
                while True:
                    got_stream, kind, _ = await browser.read()
                    if got_stream == stream and kind == 0x13:
                        break
                await browser.send(stream, 0x14, struct.pack('<I', 1048576))
        print(json.dumps(dict(phase='settle', revision=args.revision, sessions=len(sessions), clients=len(browsers),
                              attached_sessions=min(len(sessions), args.clients * 25),
                              server_pid=server_pid, seconds=args.settle)), flush=True)
        await asyncio.sleep(args.settle)
        result = await measure(server_pid, args.seconds)
        assert all(not browser.task.done() and (browser.probe_task is None or not browser.probe_task.done()) for browser in browsers), 'idle browser retired'
        assert shim_pids(runtime) == pids, 'real shim identities changed'
        # Fresh correlated control replies establish that retained sockets survived the window.
        for browser in browsers:
            body = struct.pack('<QQ', 199, 199)
            await browser.send(0, 8, body)
            while True:
                stream, kind, reply = await browser.read()
                if stream == 0 and kind == 9 and reply == body:
                    break
        print(json.dumps(dict(revision=args.revision, sessions=len(sessions), clients=len(browsers),
                              attached_sessions=min(len(sessions), args.clients * 25),
                              profile='responses-only' if args.responses_only else 'full-duplex',
                              client_probe_pongs=[browser.probe_pongs for browser in browsers], **result)), flush=True)
        if args.perf is not None:
            # Profile separately so sampling overhead cannot contaminate the table.
            # Frame-pointer callchains contain addresses, never raw stack dumps.
            assert args.profile is not None and args.profile.resolve().is_relative_to(root.parent)
            child = await asyncio.create_subprocess_exec(
                str(args.perf.resolve()), 'record', '-e', 'cpu-clock', '-F', '99', '-p', str(server_pid),
                '--call-graph', 'fp', '-o', str(args.profile.resolve()), '--', 'sleep', '10',
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            assert await child.wait() == 0, 'fixture profile capture failed'
            print(json.dumps(dict(phase='profile', revision=args.revision, clients=len(browsers))), flush=True)
    finally:
        for browser in browsers:
            await browser.close()
        subprocess.run(['systemctl', 'stop', unit], check=False)
        subprocess.run(['systemctl', 'reset-failed', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Managed login/shim scopes may outlive the server's control group.
        # Never enumerate or signal peers outside this unique runtime directory.
        cleanup_pids = shim_pids(runtime)
        for pid in cleanup_pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for _ in range(100):
            live = [pid for pid in cleanup_pids if Path(f'/proc/{pid}').exists()]
            if not live:
                break
            await asyncio.sleep(.05)
        assert not live, 'fixture shim teardown incomplete'
        assert server_pid is None or not Path(f'/proc/{server_pid}').exists(), 'fixture server teardown incomplete'
        print(json.dumps(dict(phase='cleanup', server_pid=server_pid,
                              shim_pids=cleanup_pids, remaining_shims=live)), flush=True)
        shutil.rmtree(root)


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--sessions', type=int, default=128)
    parser.add_argument('--clients', type=int, choices=(0, 1, 6), required=True)
    parser.add_argument('--settle', type=float, default=60)
    parser.add_argument('--seconds', type=float, default=60)
    parser.add_argument('--responses-only', action='store_true')
    parser.add_argument('--perf', type=Path)
    parser.add_argument('--profile', type=Path)
    options = parser.parse_args()
    # Only source locations enter a failed receipt; exception text may contain authority.
    try:
        asyncio.run(run(options))
    except Exception as error:
        import traceback
        for frame in traceback.extract_tb(error.__traceback__):
            print(f'FIXTURE failure_file={frame.filename} failure_line={frame.lineno}', flush=True)
        raise SystemExit(1) from None
