#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Home-router bufferbloat profile: a shaped bottleneck with a deep queue (D381, #260).

First built by J512 on the perf VM; J638 brought it onto dev (D393: tooling
lives on dev with its tests). Run as root inside the D348 pinned runner
(`perf-all.sh --bufferbloat`), which takes the lock, places the CPUs and
restores them. Only job-owned namespaces, sockets and processes are changed. A
separate router namespace keeps propagation delay apart from the rate queues.
The kit README ("Bufferbloat profile") documents the topology and its limits.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess as sp
import sys
import tempfile
import time

# perf-all.sh row engines -> this profile's engines. `kernel` here is plain kernel
# WireGuard (perf-all's `kernel-plain`), never NetBird.
PLAN_ENGINES = {'underlay': 'bare', 'gotatun': 'gotatun', 'kernel-plain': 'kernel', 'wireguard-go': 'wireguard-go'}


def read_plan(plan):
    """Return the profile engines in plan order and the GotaTun row's binary, if any."""
    engines, gotatun = [], None
    for line in Path(plan).read_text().splitlines():
        if not line.strip():
            continue
        tag, engine, binary = (line.split('\t') + ['', ''])[:3]
        if engine not in PLAN_ENGINES:
            raise ValueError(f'row {tag}: the bufferbloat profile cannot run engine {engine}')
        engines.append(PLAN_ENGINES[engine])
        if engine == 'gotatun':
            gotatun = Path(binary)
    return engines, gotatun


def ethtool():
    """The ethtool to use: H2H_ETHTOOL_BIN, else PATH (hosts may keep it in /nix/store)."""
    found = os.environ.get('H2H_ETHTOOL_BIN') or shutil.which('ethtool') or '/usr/sbin/ethtool'
    if not os.access(found, os.X_OK):
        raise RuntimeError(f'ethtool is required to turn off underlay offloads: {found}')
    return found


def run(*args, **kwargs):
    """Run a checked command without echoing key-bearing configuration."""
    try:
        return sp.run(list(map(str, args)), check=True, capture_output=True, text=True, **kwargs).stdout
    except sp.CalledProcessError as error:
        if 'tc' in args:
            print(error.stderr, file=sys.stderr, flush=True)
        raise


def ns(name, *args):
    """Run in a job-owned network namespace."""
    return run('ip', 'netns', 'exec', name, *args)


def quantile(values, percentile):
    """Return the nearest-rank percentile of received RTTs."""
    return sorted(values)[max(0, math.ceil(len(values) * percentile) - 1)]


class Case:
    """Own a complete topology and clean up only its own processes and links."""
    def __init__(self, args, engine, output):
        """Save one case's immutable settings and cleanup inventory."""
        self.args, self.engine, self.output = args, engine, output
        self.names = ['j512a', 'j512r', 'j512b']
        self.pids, self.logs = [], []
        self.units = []
        self.audit = None
        self.sockets = []
        self.paused = {}
        self.keys = Path(tempfile.mkdtemp(prefix='j512-keys-', dir='/run'))
        self.addresses = ['10.251.1.1', '10.251.2.1']

    def spawn(self, namespace, label, *cmd, paused=False):
        """Keep the real child PID and its evidence log for exact cleanup."""
        log = (self.output / f'{label}.log').open('w')
        self.logs.append(log)
        command = ['ip', 'netns', 'exec', namespace, *map(str, cmd)]
        environment = None
        pidfile = self.output / f'{label}.pid'
        if os.environ.get('H2H_CPUSET_PIN') == '1':
            mask = '1-2' if namespace == 'j512a' else '3-4'
            scopes = self.output / 'scopes'
            scopes.mkdir(exist_ok=True)
            environment = {**os.environ, 'H2H_KIT': str(self.args.kit), 'H2H_RUN': str(scopes), 'H2H_RESULTS': str(self.output.parent), 'H2H_CASE': self.engine, 'H2H_SCOPE_LOG': str(self.output / f'{label}.scope.log'), 'H2H_SCOPE_STDOUT': str(self.output / f'{label}.log'), 'H2H_SCOPE_STDERR': str(self.output / f'{label}.log'), 'H2H_SCOPE_PAUSE': '1' if paused else '0'}
            command = ['bash', '-c', 'source "$H2H_KIT/lib/common.sh"; mask=$1; file=$2; shift 2; h2h_scope_spawn pid "$mask" "$@"; printf "%s\\n" "$pid" > "$file"; wait "$H2H_SCOPE_CLIENT_PID"', 'j512-scope', mask, str(pidfile), *command]
        process = sp.Popen(command, stdout=log, stderr=sp.STDOUT, env=environment)
        self.pids.append(process)
        if environment is not None:
            deadline = time.monotonic() + 12
            while not pidfile.exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f'scope failed: {label}; see its scope log')
                # sleep: the existing helper publishes the real command PID.
                time.sleep(.05)
            child = int(pidfile.read_text().strip())
            if paused:
                while 'State:\tT' not in Path(f'/proc/{child}/status').read_text():
                    if time.monotonic() > deadline:
                        raise RuntimeError('scope did not pause before the audit')
                    # sleep: wait for STOP before a later CONT can race it.
                    time.sleep(.01)
                self.paused[process.pid] = child
        return process

    def resume(self, process):
        """Resume an already placed measurement scope after a clean preflight."""
        child = self.paused.pop(process.pid, None)
        if child is not None:
            os.kill(child, signal.SIGCONT)

    def setup(self):
        """Build a routed underlay with separate 6 ms propagation stages."""
        for name in self.names:
            run('ip', 'netns', 'add', name)
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
            ns(name, 'sysctl', '-qw', 'net.ipv4.tcp_congestion_control=cubic')
        for side, subnet in [('a', 1), ('b', 2)]:
            end = f'j512{side}'
            run('ip', 'link', 'add', 'e0', 'netns', end, 'type', 'veth', 'peer', 'name', f'r{side}', 'netns', 'j512r')
            for namespace, dev, address in [(end, 'e0', f'10.251.{subnet}.1'), ('j512r', f'r{side}', f'10.251.{subnet}.254')]:
                ns(namespace, 'ip', 'addr', 'add', address + '/24', 'dev', dev)
                ns(namespace, 'ip', 'link', 'set', dev, 'up')
                ns(namespace, ethtool(), '-K', dev, 'tso', 'off', 'gso', 'off', 'gro', 'off')
            ns(end, 'ip', 'route', 'add', 'default', 'via', f'10.251.{subnet}.254')
            if os.environ.get('H2H_CPUSET_PIN') == '1':
                ns(end, 'sh', '-c', 'echo ' + ('6' if side == 'a' else '18') + ' > /sys/class/net/e0/queues/rx-0/rps_cpus')
            ns(end, 'tc', 'qdisc', 'add', 'dev', 'e0', 'root', 'netem', 'delay', '6ms', 'limit', '10000')
        ns('j512r', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        for dev, rate, cap in [('ra', '481.5mbit', self.args.down_bytes), ('rb', '778.9mbit', self.args.up_bytes)]:
            ns('j512r', 'tc', 'qdisc', 'add', 'dev', dev, 'root', 'handle', '1:', 'htb', 'default', '1')
            ns('j512r', 'tc', 'class', 'add', 'dev', dev, 'parent', '1:', 'classid', '1:1', 'htb', 'rate', rate, 'ceil', rate, 'burst', '32k', 'cburst', '32k', 'quantum', '1514')
            leaf = ['bfifo', 'limit', str(cap)] if self.args.profile == 'fifo' else ['fq_codel', 'limit', '10000', 'target', '5ms', 'interval', '100ms', 'quantum', '1514', 'noecn']
            ns('j512r', 'tc', 'qdisc', 'add', 'dev', dev, 'parent', '1:1', 'handle', '10:', *leaf)
            if self.args.profile == 'fq_codel':
                # A veth can preserve a tunnel's inner skb hash. A physical
                # router sees only the outer UDP tuple, so explicitly put all
                # packets for that peer socket into one fq_codel flow bucket.
                # Classify every packet: attaching only a UDP flower filter
                # makes fq_codel drop unmatched ARP/control packets. The flow
                # classifier hashes outer header fields, never cached skb hash.
                ns('j512r', 'tc', 'filter', 'add', 'dev', dev, 'parent', '10:', 'protocol', 'all', 'prio', '1', 'handle', '1', 'flow', 'hash', 'keys', 'src,dst,proto,proto-src,proto-dst', 'divisor', '1024', 'baseclass', '10:1')
        if self.engine != 'bare':
            self.tunnel()
        for i, name in enumerate(['j512a', 'j512b']):
            self.spawn(name, f'server-{i}', self.args.kit / 'bin/h2h', 'net-server', '--bind', '0.0.0.0:5201')
        # sleep: allow listeners to bind before checking the actual route.
        time.sleep(.3)
        ns('j512a', 'ping', '-n', '-c', '3', '-i', '.1', '-W', '2', self.addresses[1])

    def tunnel(self):
        """Configure identical two-peer tunnels using the existing kit helpers."""
        run('python3', '-I', self.args.kit / 'lib/gotatun_uapi.py', 'keys', self.keys)
        run('python3', '-I', self.args.kit / 'lib/wg_cli_keys.py', self.keys)
        for i, side in enumerate(['a', 'b']):
            name, interface = f'j512{side}', 'wgA' if side == 'a' else 'wgB'
            if self.engine == 'kernel':
                ns(name, 'ip', 'link', 'add', interface, 'type', 'wireguard')
            else:
                socket = Path(f'/var/run/wireguard/{interface}.sock')
                if socket.exists():
                    raise RuntimeError('job socket already exists; refusing to remove foreign state')
                if self.engine == 'gotatun':
                    proc = self.spawn(name, f'engine-{side}', 'env', 'WG_SUDO=1', 'WG_LOG_LEVEL=error', 'WG_LOG_FILE=' + str(self.output / f'gotatun-{side}.log'), self.args.gotatun, '--foreground', '--disable-drop-privileges', interface)
                else:
                    proc = self.spawn(name, f'engine-{side}', 'env', 'WG_PROCESS_FOREGROUND=1', self.args.kit / 'bin/wireguard-go', interface)
                deadline = time.monotonic() + 10
                while not socket.exists():
                    if proc.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(f'{self.engine} failed to create UAPI socket')
                    # sleep: poll readiness, never part of a measured sample.
                    time.sleep(.05)
                self.sockets.append(socket)
            peer = 'b' if side == 'a' else 'a'
            config = (f'[Interface]\nPrivateKey = {(self.keys / (side + ".wg.private")).read_text().strip()}\nListenPort = {51820+i}\n'
                      f'[Peer]\nPublicKey = {(self.keys / (peer + ".wg.public")).read_text().strip()}\n'
                      f'Endpoint = {self.addresses[1-i]}:{51821-i}\nAllowedIPs = 10.252.0.{2-i}/32\n')
            path = self.keys / f'{side}.conf'
            path.write_text(config)
            path.chmod(0o600)
            ns(name, self.args.kit / 'bin/wg', 'setconf', interface, path)
            ns(name, 'ip', 'addr', 'add', f'10.252.0.{i+1}/24', 'dev', interface)
            ns(name, 'ip', 'link', 'set', interface, 'mtu', '1420', 'up')
        self.addresses = ['10.252.0.1', '10.252.0.2']
        shutil.rmtree(self.keys)

    def sample(self, mode):
        """Overlap counted 100 Hz ICMP with eight TCP flows per loaded direction.

        Leave a large guard before load end: a ping deadline would censor the
        final in-flight replies, falsely counting queue delay as packet loss.
        """
        duration = self.args.seconds
        clients = []
        for direction, name, target in [('down', 'j512b', self.addresses[0]), ('up', 'j512a', self.addresses[1])]:
            if mode in [direction, 'both']:
                clients.append((direction, self.spawn(name, f'{mode}-{direction}', self.args.kit / 'bin/h2h', 'net-tput', '--to', target + ':5201', '--flows', '8', '--seconds', str(duration + 6), paused=True)))
        path = self.output / f'{mode}-ping.log'
        outer = None
        if self.engine != 'bare':
            outer = self.spawn('j512a', f'{mode}-underlay-ping', 'ping', '-D', '-O', '-n', '-i', '.01', '-c', str(duration*80), '-W', '1', '10.251.2.1', paused=True)
        probe = self.spawn('j512a', f'{mode}-ping', 'ping', '-D', '-O', '-n', '-i', '.01', '-c', str(duration*80), '-W', '1', self.addresses[1], paused=True)
        self.start_audit(mode)
        load_started = time.monotonic()
        for _, child in clients:
            self.resume(child)
        # sleep: exclude TCP startup; sample the central loaded interval.
        time.sleep(2 if clients else .1)
        started = time.monotonic()
        if outer:
            self.resume(outer)
        self.resume(probe)
        if probe.wait(timeout=duration+4):
            raise RuntimeError('RTT probe failed')
        probe_seconds = time.monotonic() - started
        load_elapsed = time.monotonic() - load_started
        if clients and (load_elapsed >= duration + 6 or any(child.poll() is not None for _, child in clients)):
            raise RuntimeError('ping window outlasted the guarded load interval; case excluded')
        for dev in ['ra', 'rb']:
            (self.output / f'{mode}-{dev}-qdisc.txt').write_text(ns('j512r', 'tc', '-s', '-d', 'qdisc', 'show', 'dev', dev))
            (self.output / f'{mode}-{dev}-filters.txt').write_text(ns('j512r', 'tc', '-s', 'filter', 'show', 'dev', dev, 'parent', '10:'))
        goodput = {}
        for direction, child in clients:
            child.wait(timeout=15)
            if child.returncode:
                raise RuntimeError('throughput child failed')
            data = json.loads((self.output / f'{mode}-{direction}.log').read_text())
            goodput[direction] = data['gbit_per_s'] * 1000
        values = [float(v) for v in re.findall(r'time=([\d.]+) ms', path.read_text())]
        sent = int(re.search(r'(\d+) packets transmitted', path.read_text()).group(1))
        lost = sent - len(values)
        if not values:
            raise RuntimeError('no RTT replies')
        from pingstat import stats
        ping_stats = stats([path], expected_sent=sent)
        result = dict(mode=mode, samples=len(values), sent=sent, lost=lost, mean_ms=statistics.mean(values), p50_ms=statistics.median(values), p99_ms=ping_stats['p99_loss_aware_ms'], goodput_mbit=goodput)
        result['probe_seconds'] = probe_seconds
        result['load_elapsed_at_probe_end_seconds'] = load_elapsed if clients else None
        if outer:
            outer.wait(timeout=3)
            result['underlay'] = stats([self.output / f'{mode}-underlay-ping.log'], expected_sent=sent)
        cores = self.stop_audit()
        if cores is not None:
            result['cores_busy'] = cores
        print(json.dumps(dict(engine=self.engine, **result)), flush=True)
        return result

    def start_audit(self, mode):
        """Reuse the kit's D348 readiness and interference sampler unchanged."""
        if os.environ.get('H2H_CPUSET_PIN') != '1':
            return
        directory = self.output / f'cpuset-{mode}'
        self.audit_directory = directory
        directory.mkdir()
        ready = directory / 'ready'
        environment = {**os.environ, 'H2H_CPUSET_AUDIT_CASE': 'mesh-kernel-plain' if self.engine == 'kernel' else 'mesh-gotatun', 'H2H_CPUSET_AUDIT_READY_FILE': str(ready)}
        log = (directory / 'audit.log').open('w')
        self.logs.append(log)
        self.audit = sp.Popen(['python3', '-I', str(self.args.kit / 'lib/cpuset_audit.py'), str(directory), str(os.getpid())], env=environment, stdout=log, stderr=sp.STDOUT)
        deadline = time.monotonic() + 10
        while not ready.exists():
            if self.audit.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('D348 audit did not reach clean readiness')
            # sleep: readiness polling precedes every measured interval.
            time.sleep(.05)

    def stop_audit(self):
        """Require a clean, nonempty audit before accepting a pinned case."""
        if self.audit is None:
            return
        self.audit.terminate()
        status = self.audit.wait(timeout=10)
        self.audit = None
        summary = json.loads((self.audit_directory / 'summary.json').read_text())
        if status or not summary.get('clean') or summary.get('samples', 0) < 1:
            raise RuntimeError('D348 audit rejected this case; see cpuset-audit/summary.json')
        # Which CPUs the engine really used (kernel crypto can run on housekeeping; J638).
        from cpu_split import split
        cores = split((self.audit_directory / 'proc-stat.before.txt').read_text(),
                      (self.audit_directory / 'proc-stat.after.txt').read_text())
        (self.audit_directory / 'cpu-split.json').write_text(json.dumps(cores, indent=2) + '\n')
        return cores['cores_busy']

    def close(self):
        """Stop exact children, reap them, and remove only job-owned state."""
        if self.audit is not None:
            self.audit.terminate()
            self.audit.wait(timeout=10)
        inventory = self.output / 'cpuset-pids.tsv'
        if inventory.exists():
            entries = [line.split('\t') for line in inventory.read_text().splitlines()]
            self.units = [entry[2] for entry in entries]
            # A setup error can leave a measured command stopped. Resume only
            # PIDs still in their recorded scope so TERM can finish promptly;
            # an exited PID must never target a later unrelated process.
            for pid, _, unit in entries:
                try:
                    group = Path(f'/proc/{pid}/cgroup').read_text()
                    if '/' + unit in group:
                        os.kill(int(pid), signal.SIGCONT)
                except ProcessLookupError:
                    pass
                except FileNotFoundError:
                    pass
        for unit in reversed(self.units):
            sp.run(['systemctl', 'stop', unit], capture_output=True)
        for child in reversed(self.pids):
            if child.poll() is None:
                child.terminate()
        for child in reversed(self.pids):
            try:
                child.wait(timeout=3)
            except sp.TimeoutExpired:
                child.kill()
                child.wait()
        for log in self.logs:
            log.close()
        for name in reversed(self.names):
            sp.run(['ip', 'netns', 'del', name], capture_output=True)
        for socket in self.sockets:
            socket.unlink(missing_ok=True)
        shutil.rmtree(self.keys, ignore_errors=True)


def main():
    """Run one bounded hold, preserving partial results on any case failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True, help="the hold's rows.tsv (perf-all.sh --bufferbloat)")
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--profile', choices=['fifo', 'fq_codel'], required=True)
    parser.add_argument('--down-bytes', type=int, default=3500000)
    parser.add_argument('--up-bytes', type=int, default=3500000)
    parser.add_argument('--seconds', type=int, default=12)
    parser.add_argument('--modes', nargs='+', choices=['idle', 'down', 'up', 'both'], default=['idle', 'down', 'up', 'both'])
    args = parser.parse_args()
    sys.path.insert(0, str(args.kit / 'lib'))
    args.engines, args.gotatun = read_plan(args.plan)
    if 'gotatun' in args.engines and not (args.gotatun and os.access(args.gotatun, os.X_OK)):
        parser.error('the gotatun row needs an executable --binary')
    args.out.mkdir(parents=True, exist_ok=True)
    metadata = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    metadata['kernel'] = run('uname', '-r').strip()
    metadata['cpuset'] = Path('/sys/fs/cgroup/perf.slice/cpuset.cpus.effective').read_text().strip()
    metadata['d348_pinned'] = os.environ.get('H2H_CPUSET_PIN') == '1'
    metadata['sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in [Path(__file__), *([args.gotatun] if args.gotatun else []), args.kit / 'bin/h2h', args.kit / 'bin/wireguard-go', args.kit / 'bin/wg']}
    (args.out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    rows = []
    for engine in args.engines:
        output = args.out / engine
        output.mkdir()
        case = Case(args, engine, output)
        try:
            case.setup()
            samples = [case.sample(mode) for mode in args.modes]
            rows.append(dict(engine=engine, profile=args.profile, samples=samples))
        finally:
            case.close()
            (args.out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    print('BUFFERBLOAT_EXIT=0', flush=True)


if __name__ == '__main__':
    main()
