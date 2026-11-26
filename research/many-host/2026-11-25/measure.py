#!/usr/bin/env python3
"""Many-host server measurements, #562 (J1057).

Starts the `many_host_server_fixture` test (crates/infraternal-server/src/
remote_many_host_tests.rs): a disposable in-process server whose CA is unlocked
by the test's own memory-only administrator, plus N real `infraternal agent
join` processes enrolled over HTTPS. This script then plays the browsers
(wire-level, over TLS to the test CA) and samples /proc of the server process
and of the agents. Nothing touches a shared prod, test or QA server.

Per host count it prints one JSON object:
  enrol      per-host spawn -> identity published, total, server and agent memory after the last join
  idle_bare  server/agents CPU and schedule-ins per second with no browser socket open
  idle_view  the same with one visible browser socket and one attached terminal
  echo_one   key-to-echo on one host while every other host is idle
  echo_many  key-to-echo while K hosts each have a typist
Key-to-echo is Input sent -> echoed Output received on the browser socket.
Run it under `perf-run` for timing numbers.
"""
import argparse, asyncio, base64, json, os, random, signal, socket, ssl
import struct, subprocess, sys, time, uuid
from pathlib import Path

PAGE = os.sysconf('SC_PAGE_SIZE')
HZ = os.sysconf('SC_CLK_TCK')


def varint(v):
    out = bytearray()
    while True:
        b = v & 127
        v >>= 7
        if v:
            out.append(b | 128)
        else:
            out.append(b)
            return bytes(out)


def integer(data, off):
    v = 0
    for shift in range(0, 35, 7):
        b = data[off]; off += 1
        v |= (b & 127) << shift
        if b < 128:
            return v, off
    raise ValueError('varint')


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


class Term:
    """One attached terminal stream on a viewer socket."""
    def __init__(self, sid, stream):
        self.sid, self.stream = sid, stream
        self.out = bytearray()
        self.ready = asyncio.Event()
        self.attached = asyncio.Event()
        self.in_seq = 0
        self.sent = []          # monotonic send time per input byte (index = in_seq)
        self.echoed = 0         # bytes of echo matched after `ready`
        self.echo_base = None   # output length when ready fired
        self.acked = 0
        self.echo_lat = []
        self.ack_lat = []
        self.measure = False


class Viewer:
    """A wire-level browser socket: answers pings, demuxes terminal streams."""
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        self.ctrl = asyncio.Queue()
        self.terms = {}
        self.frames = {}
        self.lock = asyncio.Lock()
        self.task = asyncio.create_task(self.rx())

    @classmethod
    async def connect(cls, manifest, hidden=False):
        port, token = manifest['port'], manifest['cookie']
        ctx = ssl.create_default_context(cadata=manifest['root_pem'])
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT   # the test CA has no Authority Key Identifier; Python 3.13 insists
        r, w = await asyncio.open_connection('127.0.0.1', port, ssl=ctx, server_hostname='localhost')
        key = base64.b64encode(os.urandom(16)).decode()
        w.write((f'GET /v1/ws HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: https://localhost:{port}\r\n'
                 f'Cookie: __Host-infraternal={token}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                 f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        await w.drain()
        resp = await r.readuntil(b'\r\n\r\n')
        assert resp.startswith(b'HTTP/1.1 101'), resp[:80]
        v = cls(r, w)
        assert (await v.cget())[1] == 0
        info = b'j1057-many-hosts'
        # Hello caps bit 2: viewer visibility notices (#244); a hidden viewer parks its probes.
        await v.send(0, 0, struct.pack('<HQ', 1, 4 if hidden else 0) + varint(len(info)) + info)
        assert (await v.cget())[1] == 1
        if hidden:
            await v.send(0, 0x33, struct.pack('<I', 0) + b'{"topic":"connection.visibility","hidden":true}')
        return v

    async def cget(self):
        m = await asyncio.wait_for(self.ctrl.get(), 30)
        assert m is not None, 'viewer closed'
        return m

    def send_nowait(self, stream, kind, body=b''):
        wire = varint(stream) + varint(len(body) + 1) + bytes([kind]) + body
        mask = os.urandom(4)
        n = len(wire)
        h = bytes([0x82])
        if n < 126:
            h += bytes([0x80 | n])
        elif n < 65536:
            h += b'\xfe' + struct.pack('!H', n)
        else:
            h += b'\xff' + struct.pack('!Q', n)
        mk = (mask * (n // 4 + 1))[:n]
        self.w.write(h + mask + bytes(a ^ b for a, b in zip(wire, mk)))

    async def send(self, stream, kind, body=b''):
        self.send_nowait(stream, kind, body)
        await self.w.drain()

    def pong(self, opcode, payload):
        mask = os.urandom(4)
        self.w.write(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask +
                     bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    async def rx(self):
        try:
            while True:
                hdr = await self.r.readexactly(2)
                op, n = hdr[0] & 15, hdr[1] & 127
                if n == 126:
                    n = struct.unpack('!H', await self.r.readexactly(2))[0]
                elif n == 127:
                    n = struct.unpack('!Q', await self.r.readexactly(8))[0]
                wire = await self.r.readexactly(n)
                now = time.monotonic()
                self.frames[f'ws{op}'] = self.frames.get(f'ws{op}', 0) + 1
                if op == 9:
                    self.pong(10, wire); continue
                if op == 8:
                    print(json.dumps(dict(phase='socket_close', code=struct.unpack('!H', wire[:2])[0] if len(wire) >= 2 else None, reason=wire[2:80].decode('utf8', 'replace'))), flush=True)
                    raise EOFError
                if op != 2:
                    continue
                off = 0
                while off < len(wire):
                    stream, off = integer(wire, off)
                    ln, off = integer(wire, off)
                    kind, body = wire[off], wire[off + 1:off + ln]
                    off += ln
                    self.frames[kind] = self.frames.get(kind, 0) + 1
                    if kind == 8:
                        self.send_nowait(stream, 9, body)
                        continue
                    t = self.terms.get(stream)
                    if t is None:
                        self.ctrl.put_nowait((stream, kind, body)); continue
                    if kind == 0x13:
                        acked = struct.unpack('<Q', body[:8])[0]
                        if not t.attached.is_set():
                            t.in_seq = acked; t.attached.set()
                        elif t.measure:
                            for i in range(t.acked, min(acked, len(t.sent))):
                                if t.sent[i] is not None:
                                    t.ack_lat.append(now - t.sent[i])
                        t.acked = max(t.acked, acked)
                    elif kind in (0x11, 0x15):
                        data = body[8:]
                        t.out += data
                        if not t.ready.is_set():
                            if b'RDYX' in t.out:
                                t.ready.set(); t.echo_base = len(t.out)
                        elif t.measure:
                            for _ in range(len(data)):
                                i = t.echoed
                                if i < len(t.sent) and t.sent[i] is not None:
                                    t.echo_lat.append(now - t.sent[i])
                                t.echoed += 1
                        if len(t.out) > 65536:
                            del t.out[:-4096]
                    elif kind == 0x33:
                        try:
                            ty = json.loads(body[4:]).get('type')
                        except ValueError:
                            ty = 'bad'
                        self.frames['ev:' + str(ty)] = self.frames.get('ev:' + str(ty), 0) + 1
                    elif kind == 0x0f:
                        print(json.dumps(dict(phase='stream_close', stream=stream, body=body[2:60].decode('utf8', 'replace'))), flush=True)
        except (EOFError, asyncio.IncompleteReadError, ConnectionError):
            self.ctrl.put_nowait(None)


# ---------- process observation (read-only /proc) ----------

def children(pid):
    out = []
    try:
        for t in Path(f'/proc/{pid}/task').iterdir():
            out += [int(x) for x in (t / 'children').read_text().split()]
    except FileNotFoundError:
        pass
    return out


def cmdline(pid):
    try:
        return Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    except FileNotFoundError:
        return []


def proc_sample(pid, lite=False):
    """CPU ticks (all threads), schedule-ins (all threads), RSS/PSS kB.

    `lite` skips smaps_rollup and the fd count: with thousands of shells below
    the agents those two reads would dominate the sampler's own cost.
    """
    try:
        st = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        cpu = int(st[11]) + int(st[12])
        sched = 0; runns = 0
        for t in Path(f'/proc/{pid}/task').iterdir():
            f = (t / 'schedstat').read_text().split()
            runns += int(f[0]); sched += int(f[2])
        roll = {}
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            k, _, v = line.partition(':')
            if k in ('VmRSS', 'RssAnon', 'RssFile', 'RssShmem', 'VmHWM', 'Threads'):
                roll[k] = int(v.split()[0])
        if lite:
            return dict(cpu_ns=cpu * 1_000_000_000 // HZ, sched=sched, rss_kb=roll.get('VmRSS', 0), pss_kb=0,
                        anon_kb=roll.get('RssAnon', 0), hwm_kb=roll.get('VmHWM', 0), threads=roll.get('Threads', 0), fds=-1)
        try:
            # Hardened (non-dumpable) processes keep smaps_rollup and fd/ root-only.
            for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines()[1:]:
                k, v = line.split(':', 1)
                if k == 'Pss':
                    roll['Pss'] = int(v.split()[0])
            fds = len(os.listdir(f'/proc/{pid}/fd'))
        except PermissionError:
            fds = -1
        threads = roll.get('Threads', 0)
        return dict(cpu_ns=cpu * 1_000_000_000 // HZ, sched=sched, rss_kb=roll.get('VmRSS', 0), pss_kb=roll.get('Pss', 0),
                    anon_kb=roll.get('RssAnon', 0), hwm_kb=roll.get('VmHWM', 0), threads=threads, fds=fds)
    except (FileNotFoundError, ProcessLookupError):
        return None


def group_sample(pids):
    agg = dict(cpu_ns=0, sched=0, rss_kb=0, pss_kb=0, anon_kb=0, n=0)
    per = {}
    for p in pids:
        s = proc_sample(p)
        if s:
            per[p] = s
            for k in ('cpu_ns', 'sched', 'rss_kb', 'pss_kb', 'anon_kb'):
                agg[k] += s[k]
            agg['n'] += 1
    return agg, per


def delta(a, b, secs):
    return dict(cpu_pct_core=(b['cpu_ns'] - a['cpu_ns']) / secs / 1e7,
                wakeups_per_s=(b['sched'] - a['sched']) / secs,
                rss_mib=b['rss_kb'] / 1024, anon_mib=b['anon_kb'] / 1024, pss_mib=b['pss_kb'] / 1024, n=b.get('n', 1))




def sample_group(pids):
    """Sum CPU ticks, schedule-ins and memory over the live pids in `pids`."""
    agg = dict(cpu_ns=0, sched=0, rss_kb=0, anon_kb=0, pss_kb=0, n=0)
    for p in pids:
        s = proc_sample(p, lite=True)
        if s:
            for k in ('cpu_ns', 'sched', 'rss_kb', 'anon_kb'):
                agg[k] += s[k]
            agg['n'] += 1
    return agg


def scope_pids(root):
    """Every process of this run that is not an infraternal agent or the server.

    Shims and shells are not always children of the agent (they may be started in
    their own scope), so look at our cgroup first and at the run's state directory
    in each command line second.
    """
    mine = set()
    try:
        path = Path('/proc/self/cgroup').read_text().strip().split(':')[-1]
        mine = {int(x) for x in Path(f'/sys/fs/cgroup{path}/cgroup.procs').read_text().split()}
    except (OSError, ValueError):
        pass
    for d in Path('/proc').iterdir():
        if d.name.isdigit() and int(d.name) not in mine:
            try:
                if str(root).encode() in (d / 'cmdline').read_bytes():
                    mine.add(int(d.name))
            except OSError:
                pass
    return mine


def descendants(pid):
    """All live descendants of `pid` (agents spawn shims and shells)."""
    out, todo = [], [pid]
    while todo:
        for c in children(todo.pop()):
            out.append(c); todo.append(c)
    return out


class Observer:
    """Samples the server process, the agents and the shims below them."""
    def __init__(self, server, agents, root):
        self.server, self.agents, self.root = server, agents, root

    def sample(self):
        skip = {self.server, os.getpid(), *self.agents}
        pid = os.getpid()
        while pid > 1:                       # our own wrappers (timeout, bash, sudo) are not part of the load
            try:
                pid = int(Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[1])
            except (OSError, ValueError):
                break
            skip.add(pid)
        shims = [p for p in set(scope_pids(self.root)) | {d for a in self.agents for d in descendants(a)} if p not in skip]
        return dict(server=proc_sample(self.server), agents=sample_group(self.agents),
                    below=sample_group(shims))

    @staticmethod
    def window(a, b, secs):
        out = {}
        for k in ('server', 'agents', 'below'):
            out[k] = delta(a[k], b[k], secs)
        out['server'].update(threads=b['server']['threads'], fds=b['server']['fds'])
        return out


def threads_sched(pid):
    out = {}
    for t in Path(f'/proc/{pid}/task').iterdir():
        try:
            out[t.name] = ((t / 'comm').read_text().strip(), int((t / 'schedstat').read_text().split()[2]))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return out


def cgroup_mem():
    """Bytes charged to this process's cgroup (the perf-run scope has a 6 GB cap), or None."""
    try:
        path = Path('/proc/self/cgroup').read_text().strip().split(':')[-1]
        return int(Path(f'/sys/fs/cgroup{path}/memory.current').read_text())
    except (OSError, ValueError):
        return None


async def open_remote(v, call, host_id):
    """ssh.session.open on one enrolled host; returns (session uuid, seconds)."""
    t0 = time.monotonic(); refused = 0
    while True:
        act = b'ssh.session.open'
        await v.send(0, 0x30, struct.pack('<I', call) + varint(len(act)) + act + json.dumps({'host_id': host_id}).encode())
        while True:
            _, kind, body = await v.cget()
            if kind == 0x31:
                break
        if body[4] == 1:
            return uuid.UUID(json.loads(body[5:])['session_id']), time.monotonic() - t0, refused
        refused += 1
        if time.monotonic() - t0 > 60:
            raise RuntimeError(f'open refused: {body[5:200]!r}')
        await asyncio.sleep(.05)


async def attach(v, sid, stream):
    """Attach a viewer stream and turn the remote shell into raw `cat` (an echo source)."""
    t = Term(sid, stream); v.terms[stream] = t
    await v.send(stream, 0x16, sid.bytes + bytes(16))
    await asyncio.wait_for(t.attached.wait(), 30)
    await v.send(stream, 0x14, struct.pack('<I', 1 << 20))
    cmd = b"stty raw -echo; printf 'RDY%s' X; exec cat\n"
    v.send_nowait(stream, 0x10, struct.pack('<Q', t.in_seq) + cmd); t.in_seq += len(cmd)
    await v.w.drain()
    await asyncio.wait_for(t.ready.wait(), 60)
    t.sent = [None] * t.in_seq
    t.echoed = t.in_seq
    return t


async def type_keys(typers, rate, seconds):
    """Each (viewer, term) sends one byte every 1/rate s; returns pooled echo latencies in ms."""
    stop = time.monotonic() + seconds
    before = sum(len(t.sent) for _, t in typers)
    for _, t in typers:
        t.measure = True; t.acked = t.in_seq; t.echo_lat.clear(); t.ack_lat.clear()
    async def typist(v, t):
        await asyncio.sleep(random.random() / rate)
        nxt = time.monotonic()
        while True:
            nxt += 1 / rate
            if nxt > stop:
                return
            d = nxt - time.monotonic()
            if d > 0:
                await asyncio.sleep(d)
            t.sent.append(time.monotonic())
            v.send_nowait(t.stream, 0x10, struct.pack('<Q', t.in_seq) + b'k'); t.in_seq += 1
    await asyncio.gather(*(typist(v, t) for v, t in typers))
    await asyncio.sleep(1)
    echo = [x * 1000 for _, t in typers for x in t.echo_lat]
    sent = sum(len(t.sent) for _, t in typers) - before
    for _, t in typers:
        t.measure = False
    return dict(keys=sent, echoes=len(echo), p50_ms=pct(echo, 50), p90_ms=pct(echo, 90),
                p99_ms=pct(echo, 99), max_ms=max(echo) if echo else None)


async def run(a):
    root = Path(a.root).resolve()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    manifest_path, stop = root / 'manifest.json', root / 'stop'
    for p in (manifest_path, stop):
        p.unlink(missing_ok=True)
    env = dict(os.environ, INFRATERNAL_REMOTE_TEST_BINARY=a.agent_binary, INFRATERNAL_MANY_HOSTS=str(a.hosts),
               INFRATERNAL_MANY_MANIFEST=str(manifest_path), INFRATERNAL_MANY_STOP=str(stop),
               INFRATERNAL_MANY_PORT=str(a.port), INFRATERNAL_TEST_STATE_ROOT=str(root / 's'),
               INFRATERNAL_REMOTE_FIXTURE_REPOSITORY=a.repo)
    (root / 's').mkdir(mode=0o700, exist_ok=True)
    log = open(root / 'fixture.log', 'wb')
    t0 = time.monotonic()
    fx = subprocess.Popen([a.test_binary, a.test_name, '--ignored', '--exact', '--nocapture',
                           '--test-threads=1'], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    viewers = []
    result = dict(hosts=a.hosts, machine=os.uname().nodename, cores=os.cpu_count(), load_start=os.getloadavg())
    try:
        while not manifest_path.exists():
            assert fx.poll() is None, 'fixture exited before the manifest appeared; see fixture.log'
            assert time.monotonic() - t0 < 120 + a.hosts * 3, 'fixture manifest timeout'
            await asyncio.sleep(.1)
        m = json.loads(manifest_path.read_text())
        enrol = [h['enrol_ms'] for h in m['hosts']]
        agents = [h['pid'] for h in m['hosts']]
        obs = Observer(m['server_pid'], agents, root)
        await asyncio.sleep(a.settle)
        s = await asyncio.to_thread(obs.sample)
        result['enrol'] = dict(invitation_retries=sum(h.get('invitation_retries', 0) for h in m['hosts']), total_s=m['enrol_total_ms'] / 1000, p50_ms=pct(enrol, 50), p99_ms=pct(enrol, 99),
                               max_ms=max(enrol) if enrol else None, first_ms=enrol[0] if enrol else None,
                               after=dict(cgroup_mem_mib=(cgroup_mem() or 0) / 2 ** 20, server_rss_mib=s['server']['rss_kb'] / 1024, server_anon_mib=s['server']['anon_kb'] / 1024,
                                          server_threads=s['server']['threads'], server_fds=s['server']['fds'],
                                          agents_rss_mib=s['agents']['rss_kb'] / 1024, agents_anon_mib=s['agents']['anon_kb'] / 1024,
                                          agents_alive=s['agents']['n'], per_agent_rss_mib=s['agents']['rss_kb'] / 1024 / max(1, s['agents']['n'])))
        print(json.dumps(dict(phase='enrolled', hosts=a.hosts)), flush=True)

        # Idle with no browser socket at all (D81).
        th0 = threads_sched(obs.server)
        s0 = await asyncio.to_thread(obs.sample); await asyncio.sleep(a.idle_seconds); s1 = await asyncio.to_thread(obs.sample)
        th1 = threads_sched(obs.server)
        result['idle_bare'] = Observer.window(s0, s1, a.idle_seconds)
        result['idle_bare']['server_threads_wakeups_per_s'] = {
            f'{v[0]}/{k}': round((v[1] - th0.get(k, (0, 0))[1]) / a.idle_seconds, 2) for k, v in th1.items()
            if v[1] - th0.get(k, (0, 0))[1] > a.idle_seconds * 0.5}

        # T terminals on every host, opened the way a person opens them: sockets of at most
        # `--per-socket` terminals (D214's interim pool of 28), several sockets opening at once.
        total = a.hosts * a.terminals
        plan = [(h, j) for j in range(a.terminals) for h in range(a.hosts)]   # round-robin over hosts
        # Two server limits shape the load: one socket carries at most 32 terminal streams
        # (a 33rd gets Close "stream limit"), and one account may hold 16 sockets
        # (websocket.rs MAX_USER_CONNECTIONS). One socket stays free for the reconnect phase,
        # so one account can attach at most 15 x 32 = 480 terminals here.
        per_socket = a.per_socket if total <= a.per_socket * 15 else 32
        if total > per_socket * 15:
            result['account_cap'] = dict(total=total, max=per_socket * 15)
            return result
        nsock = -(-total // per_socket)
        viewers = [await Viewer.connect(m) for _ in range(nsock)]
        slots = [(viewers[i // per_socket], 2 * (i % per_socket) + 1) for i in range(total)]
        opens, attaches, refused, skipped = [], [], [0], [False]
        terms = {}                       # (host index, terminal index) -> (viewer, Term)
        sem = asyncio.Semaphore(a.open_inflight)
        t_open0 = time.monotonic()

        async def one(i):
            h, j = plan[i]
            v, stream = slots[i]
            if skipped[0]:
                return
            cg = cgroup_mem()
            if cg is not None and cg > a.mem_cap_gib * 2 ** 30:     # stop before the scope's OOM killer does
                skipped[0] = True
                return
            async with sem, v.lock:      # one open at a time per socket: replies are matched in order
                sid, secs, ref = await open_remote(v, i + 1, m['hosts'][h]['host_id'])
                refused[0] += ref
                opens.append(secs)
                t1 = time.monotonic()
                t = await attach(v, sid, stream)
                attaches.append(time.monotonic() - t1)
                terms[(h, j)] = (v, t)

        s0 = await asyncio.to_thread(obs.sample)
        await asyncio.gather(*(one(i) for i in range(total)))
        open_wall = time.monotonic() - t_open0
        s1 = await asyncio.to_thread(obs.sample)
        result['terminals'] = dict(per_host=a.terminals, per_socket=per_socket, total=total, opened=len(opens), memory_capped=skipped[0], cgroup_mem_mib=(cgroup_mem() or 0) / 2 ** 20, sockets=nsock, open_inflight=a.open_inflight,
                                   wall_s=open_wall, opens_per_s=total / open_wall, refused_retries=refused[0],
                                   open_p50_ms=pct(opens, 50) * 1000, open_p99_ms=pct(opens, 99) * 1000, open_max_ms=max(opens) * 1000,
                                   attach_p50_ms=pct(attaches, 50) * 1000, attach_p99_ms=pct(attaches, 99) * 1000,
                                   attach_max_ms=max(attaches) * 1000,
                                   during=Observer.window(s0, s1, open_wall))
        await asyncio.sleep(a.settle)
        # Idle with every terminal attached and visible.
        for w in viewers:
            w.frames.clear()
        s0 = await asyncio.to_thread(obs.sample); await asyncio.sleep(a.idle_seconds); s1 = await asyncio.to_thread(obs.sample)
        result['idle_view'] = Observer.window(s0, s1, a.idle_seconds)
        result['idle_view']['frames_to_viewers_per_s'] = round(sum(sum(w.frames.values()) for w in viewers) / a.idle_seconds, 1)

        # Typists: K terminals spread over the hosts (host-major), the rest stay idle.
        k = min(a.typists, total)
        picks = []
        for j in range(a.terminals):
            for h in range(a.hosts):
                if len(picks) < k:
                    picks.append((h, j))
        picks = [x for x in picks if x in terms]
        typers = [terms[x] for x in picks]
        s0 = await asyncio.to_thread(obs.sample)
        t_s = time.monotonic()
        result['echo'] = await type_keys(typers, a.rate, a.type_seconds)
        result['echo']['typists'] = len(typers)
        s1 = await asyncio.to_thread(obs.sample)
        result['echo']['window'] = Observer.window(s0, s1, time.monotonic() - t_s)
        # One typist alone is the baseline for the same shape.
        result['echo_one'] = await type_keys(typers[:1], a.rate, a.type_seconds)

        # Reconnect (J1190 snapshot-first): drop the first socket and attach its terminals again.
        if a.skip_reattach:
            result['reattach'] = dict(n=0, wall_ms=0, p50_ms=0, p99_ms=0, skipped=True)
        else:
            first = [(h, j) for (h, j), (v, t) in terms.items() if v is viewers[0]]
            old = viewers[0]
            sids = [terms[x][1].sid for x in first]
            old.task.cancel(); old.w.close()
            v2 = await Viewer.connect(m); viewers.append(v2)
            t_r = time.monotonic(); re = []
            async def reattach(sid, stream):
                t0 = time.monotonic(); t = Term(sid, stream); v2.terms[stream] = t
                await v2.send(stream, 0x16, sid.bytes + bytes(16))
                await asyncio.wait_for(t.attached.wait(), 60)
                re.append(time.monotonic() - t0)
            await asyncio.gather(*(reattach(sid, 2 * i + 1) for i, sid in enumerate(sids)))
            result['reattach'] = dict(n=len(re), wall_ms=(time.monotonic() - t_r) * 1000, p50_ms=pct(re, 50) * 1000, p99_ms=pct(re, 99) * 1000)
        s1 = await asyncio.to_thread(obs.sample)
        # Thread ids let an offline strace count tell the server's threads from the agents'.
        result['tids'] = dict(server=[int(x.name) for x in Path(f"/proc/{m['server_pid']}/task").iterdir()],
                              agents=[int(x.name) for pid in agents for x in Path(f'/proc/{pid}/task').iterdir()])
        below = [p for p in (set(scope_pids(root)) | {d for a_ in agents for d in descendants(a_)}) - {os.getpid(), m['server_pid'], *agents}]
        pss = [proc_sample(p_) for p_ in below[:4000]]
        pss = [x for x in pss if x]
        result['below_detail'] = dict(n=len(below), pss_mib=sum(x['pss_kb'] for x in pss) / 1024, rss_mib=sum(x['rss_kb'] for x in pss) / 1024,
                                      anon_mib=sum(x['anon_kb'] for x in pss) / 1024, threads=sum(x['threads'] for x in pss),
                                      comms=sorted({Path(f'/proc/{p_}/comm').read_text().strip() for p_ in below[:200] if Path(f'/proc/{p_}/comm').exists()}))
        result['end'] = dict(cgroup_mem_mib=(cgroup_mem() or 0) / 2 ** 20, server=s1['server'], agents_rss_mib=s1['agents']['rss_kb'] / 1024,
                             below_rss_mib=s1['below']['rss_kb'] / 1024, below_n=s1['below']['n'])
        result['load_end'] = os.getloadavg()
        return result
    finally:
        for w in viewers:
            w.task.cancel()
            try:
                w.w.close()
            except Exception:
                pass
        stop.write_text('stop\n')
        try:
            fx.wait(60)
        except subprocess.TimeoutExpired:
            os.killpg(fx.pid, signal.SIGKILL); fx.wait()


if __name__ == '__main__':
    os.umask(0o077)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--test-binary', required=True, help='infraternal-server test executable (musl, release)')
    ap.add_argument('--agent-binary', required=True, help='infraternal CLI used for `agent join`')
    ap.add_argument('--repo', required=True, help='checkout holding scripts/ and crates/infraternal/tests/profile')
    ap.add_argument('--root', required=True)
    ap.add_argument('--test-name', default='runtime::remote_demo_tests::many_host::many_host_server_fixture')
    ap.add_argument('--hosts', type=int, default=10)
    ap.add_argument('--typists', type=int, default=20)
    ap.add_argument('--terminals', type=int, default=1, help='terminals per host')
    ap.add_argument('--per-socket', type=int, default=28, help='terminals per browser socket (D214 interim pool)')
    ap.add_argument('--mem-cap-gib', type=float, default=5.2, help='stop opening terminals above this cgroup memory')
    ap.add_argument('--skip-reattach', action='store_true')
    ap.add_argument('--open-inflight', type=int, default=8, help='opens in flight at once')
    ap.add_argument('--port', type=int, default=4702)
    ap.add_argument('--rate', type=float, default=8.0)
    ap.add_argument('--type-seconds', type=float, default=20)
    ap.add_argument('--idle-seconds', type=float, default=30)
    ap.add_argument('--settle', type=float, default=10)
    args = ap.parse_args()
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    print(json.dumps(asyncio.run(run(args))), flush=True)
