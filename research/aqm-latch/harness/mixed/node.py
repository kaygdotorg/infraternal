#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""One VM's side of the mixed flood-plus-TCP measurement (#260, J1249). Runs as root.

    python3 -I node.py <hub|tcp|flood>

It reads one JSON request per line on stdin (`{"cmd": name, ...arguments}`) and answers each with
one line `J {json}` on stdout. `drive.py` on the control host speaks to all three over ssh.

Everything lives in one network namespace, `j1249`, whose only link is an ipvlan (L2) child of
eth0 with its own address on the VM LAN. The namespace has no default route, and its own nft
table drops and counts anything leaving that link for an address outside the LAN, and all IPv6
(ipvlan traffic skips the host's postrouting hook, so the host egress guard cannot see it).

The namespace, every child process and every key file are removed when stdin closes (a dropped
ssh session), on SIGHUP/SIGINT/SIGTERM, and after 15 minutes without a request.
"""
import base64
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

NS = "j1249"
LINK = "j1249v"
TUN = "wgj1249"
ROOT = "/root/j1249"
BIN = f"{ROOT}/bin"
RUN = f"{ROOT}/run"
LAN = "10.70.3.0/24"
#: The hub's address inside the tunnel (the same one peersim sends to).
HUB_MESH = "10.254.0.1"
WG_PORT = 51820
BULK_PORT, ECHO_PORT, UDP_PORT = 5301, 5302, 5601
MTU = 1390
TICK = os.sysconf("SC_CLK_TCK")

#: Child processes by name; each leads its own process group.
children = {}


def sh(*args, check=True, **kw):
    """Run a command in the host namespace."""
    return subprocess.run(args, check=check, capture_output=True, text=True, **kw)


def ns(*args, **kw):
    """Run a command inside the job's namespace."""
    return sh("ip", "netns", "exec", NS, *args, **kw)


def spawn(name, argv, cpus=None, env=None, out=None, stdin=None):
    """Start a long-running child inside the namespace, in its own process group."""
    cmd = ["ip", "netns", "exec", NS]
    if cpus:
        cmd += ["taskset", "-c", cpus]
    log = open(out or f"{RUN}/{name}.log", "w")
    err = open(f"{RUN}/{name}.err", "w")
    children[name] = subprocess.Popen(
        cmd + argv, stdout=log, stderr=err, stdin=stdin or subprocess.DEVNULL,
        env={**os.environ, **(env or {})}, start_new_session=True)
    return children[name]


def stop(name):
    """Kill one child's process group and reap it."""
    child = children.pop(name, None)
    if child is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            break
        try:
            child.wait(timeout=2)
            break
        except subprocess.TimeoutExpired:
            continue


def at(epoch):
    """Block until the wall clock reads `epoch`."""
    delay = epoch - time.time()
    if delay > 0:
        # sleep: all three VMs start each step at the same wall-clock instant (NTP).
        time.sleep(delay)


def cpu_seconds(pid):
    """User plus system CPU seconds of a process, all threads."""
    with open(f"/proc/{pid}/stat") as stat:
        fields = stat.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / TICK


def per_cpu():
    """Per-CPU busy and softirq seconds since boot, from /proc/stat."""
    out = {}
    with open("/proc/stat") as stat:
        for line in stat:
            if line.startswith("cpu") and line[3].isdigit():
                name, *values = line.split()
                values = [int(v) for v in values[:8]]
                idle = values[3] + values[4]
                out[name] = {"busy": (sum(values) - idle) / TICK, "softirq": values[6] / TICK,
                             "steal": values[7] / TICK}
    return out


def snmp(text, proto):
    """The named counters of one protocol from /proc/net/snmp text."""
    names, values = [line.split()[1:] for line in text.splitlines() if line.startswith(proto + ":")]
    return dict(zip(names, map(int, values)))


def eth0_stats():
    """The physical NIC's receive counters (host namespace)."""
    base = "/sys/class/net/eth0/statistics"
    out = {}
    for name in ("rx_packets", "rx_bytes", "rx_dropped", "rx_missed_errors", "tx_dropped"):
        with open(f"{base}/{name}") as f:
            out[name] = int(f.read())
    with open("/proc/net/softnet_stat") as f:
        out["softnet_dropped"] = sum(int(line.split()[1], 16) for line in f)
    return out


def counters(table):
    """`comment -> (packets, bytes)` for every counting rule of an nft table in the namespace."""
    data = json.loads(ns("nft", "-j", "list", "table", "inet", table).stdout)
    out = {}
    for item in data["nftables"]:
        rule = item.get("rule")
        if not rule:
            continue
        for expr in rule["expr"]:
            if "counter" in expr:
                out[rule.get("comment", "?")] = [expr["counter"]["packets"], expr["counter"]["bytes"]]
    return out


def read_lines(path):
    """The JSON lines of a file, skipping a half-written last one."""
    out = []
    try:
        with open(path) as f:
            for line in f:
                if line.endswith("\n") and line.startswith("{"):
                    out.append(json.loads(line))
    except FileNotFoundError:
        pass
    return out


def wg_key():
    """A new WireGuard key pair as (private, public) base64."""
    private = sh(f"{BIN}/wg", "genkey").stdout.strip()
    public = sh(f"{BIN}/wg", "pubkey", input=private).stdout.strip()
    return private, public


# --- requests ---------------------------------------------------------------------------------

state = {}


def cmd_setup(ip):
    """Create the namespace with its guarded ipvlan link at `ip`."""
    os.makedirs(RUN, mode=0o700, exist_ok=True)
    if os.path.exists(f"/run/netns/{NS}"):
        raise RuntimeError(f"namespace {NS} already exists")
    # Passive check only: nothing is sent from the host namespace.
    if "lladdr" in sh("ip", "neigh", "show", "to", ip).stdout:
        raise RuntimeError(f"{ip} is already in use on the LAN")
    sh("ip", "netns", "add", NS)
    state["ip"] = ip
    ns("nft", "-f", "-", input=f"""table inet j1249guard {{
  chain post {{
    type filter hook postrouting priority 0; policy accept;
    oifname "{LINK}" ip daddr != {LAN} counter drop comment "outside-lan"
    oifname "{LINK}" meta nfproto ipv6 counter drop comment "ipv6"
  }}
}}
""")
    sh("ip", "link", "add", LINK, "link", "eth0", "type", "ipvlan", "mode", "l2")
    sh("ip", "link", "set", LINK, "netns", NS)
    ns("sysctl", "-qw", f"net.ipv6.conf.{LINK}.disable_ipv6=1")
    ns("sysctl", "-qw", "net.ipv4.tcp_ecn=0")
    ns("ip", "addr", "add", f"{ip}/24", "dev", LINK)
    ns("ip", "link", "set", "lo", "up")
    ns("ip", "link", "set", LINK, "up")
    return {"routes": ns("ip", "route").stdout.strip()}


def cmd_info():
    """Clock, size and load of this VM, and whatever else is using its CPUs right now."""
    top = sh("ps", "-eo", "pid,pcpu,comm", "--sort=-pcpu").stdout.splitlines()[1:6]
    return {"time": time.time(), "cpus": os.cpu_count(), "load": os.getloadavg(), "top": top,
            "kernel": os.uname().release}


def cmd_hub_keys():
    """Make the hub's key pair; returns the public key."""
    state["hub_private"], state["hub_public"] = wg_key()
    return {"public": state["hub_public"]}


def uapi(text):
    """One configuration request on the engine's control socket."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(f"/var/run/wireguard/{TUN}.sock")
    sock.sendall(text.encode())
    reply = b""
    while not reply.endswith(b"\n\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        reply += chunk
    sock.close()
    if b"errno=0" not in reply:
        raise RuntimeError(f"engine refused the configuration: {reply[-200:]!r}")


def cmd_hub_start(env, peers, tcp_ip, flood_ip, engine_cpus, sink_cpus, udp_cpus):
    """Start the engine with `env`, configure `peers` ([public base64, inner ip]) and the sinks."""
    stats = f"{RUN}/aqm"
    for name in os.listdir(RUN):
        if name.startswith(("aqm", "tcpsink", "udpsink", "engine")):
            os.unlink(f"{RUN}/{name}")
    if "GOTATUN_AQM" not in env or env["GOTATUN_AQM"] != "off":
        env = {**env, "GOTATUN_AQM_STATS_MS": "500", "GOTATUN_AQM_STATS_PATH": stats}
    engine = spawn("engine", [f"{BIN}/gotatun", "-f", "--disable-drop-privileges", "-l",
                              f"{RUN}/engine.trace", TUN], cpus=engine_cpus, env=env)
    for _ in range(100):
        if os.path.exists(f"/var/run/wireguard/{TUN}.sock"):
            break
        if engine.poll() is not None:
            raise RuntimeError("engine exited: " + open(f"{RUN}/engine.err").read()[-500:])
        # sleep: wait for the control socket.
        time.sleep(0.1)
    else:
        raise RuntimeError("engine control socket did not appear")
    text = (f"set=1\nprivate_key={base64.b64decode(state['hub_private']).hex()}\n"
            f"listen_port={WG_PORT}\nreplace_peers=true\n")
    for public, inner in peers:
        text += (f"public_key={base64.b64decode(public).hex()}\nreplace_allowed_ips=true\n"
                 f"allowed_ip={inner}/32\n")
    uapi(text + "\n")
    ns("ip", "addr", "add", f"{HUB_MESH}/16", "dev", TUN)
    ns("ip", "link", "set", TUN, "mtu", str(MTU), "up")
    ns("nft", "delete", "table", "inet", "j1249count", check=False)
    ns("nft", "-f", "-", input=f"""table inet j1249count {{
  chain in {{
    type filter hook input priority 10; policy accept;
    iifname "{LINK}" ip saddr {tcp_ip} udp dport {WG_PORT} counter comment "wire-tcp"
    iifname "{LINK}" ip saddr {flood_ip} udp dport {WG_PORT} counter comment "wire-flood"
    iifname "{TUN}" ip saddr 10.254.200.0/24 counter comment "tun-tcp"
    iifname "{TUN}" ip saddr 10.254.1.0/24 counter comment "tun-flood"
  }}
}}
""")
    spawn("tcpsink", ["python3", "-I", f"{ROOT}/tcpload.py", "sink", HUB_MESH, str(BULK_PORT),
                      str(ECHO_PORT), f"{RUN}/tcpsink.jsonl"], cpus=sink_cpus)
    spawn("udpsink", [f"{BIN}/peersim", "sink", str(UDP_PORT), "0.0.0.0"], cpus=udp_cpus,
          out=f"{RUN}/udpsink.jsonl")
    # sleep: let both sinks bind.
    time.sleep(0.5)
    for name in ("tcpsink", "udpsink"):
        if children[name].poll() is not None:
            raise RuntimeError(f"{name} exited: " + open(f"{RUN}/{name}.err").read()[-500:])
    affinity = sorted({tuple(sorted(os.sched_getaffinity(int(t))))
                       for t in os.listdir(f"/proc/{engine.pid}/task")})
    return {"pid": engine.pid, "threads": len(os.listdir(f"/proc/{engine.pid}/task")),
            "affinity": affinity}


def hub_snapshot():
    """Every counter the hub side reports, at one instant."""
    engine = children["engine"]
    text = ns("cat", "/proc/net/snmp").stdout
    socket_memory = ns("ss", "-uamnH", f"sport = :{WG_PORT}").stdout
    return {"t": time.time(), "engine_cpu_s": cpu_seconds(engine.pid), "nft": counters("j1249count"),
            "udp": snmp(text, "Udp"), "cpus": per_cpu(), "eth0": eth0_stats(),
            "skmem": socket_memory.strip()}


def cmd_hub_sample(start, stop_at):
    """Counters at the window's start and end, plus the socket queue sampled in between."""
    at(start)
    first = hub_snapshot()
    queue = []
    while time.time() < stop_at - 0.5:
        # The first number on each line is that socket's receive-queue length in bytes.
        lines = ns("ss", "-uanH", f"sport = :{WG_PORT}").stdout.splitlines()
        queue.append(sum(next(int(word) for word in line.split() if word.isdigit()) for line in lines))
        # sleep: the socket-queue sampling period.
        time.sleep(0.25)
    at(stop_at)
    return {"first": first, "last": hub_snapshot(), "recvq": queue}


def cmd_hub_stop():
    """Stop the engine and sinks; return the sinks' counters, the AQM lines and the guard counts."""
    alive = children["engine"].poll() is None
    for name in ("engine", "tcpsink", "udpsink"):
        stop(name)
    aqm = []
    for name in os.listdir(RUN):
        if name.startswith("aqm."):
            with open(f"{RUN}/{name}") as f:
                aqm += f.read().splitlines()
    try:
        os.unlink(f"/var/run/wireguard/{TUN}.sock")
    except FileNotFoundError:
        pass
    return {"engine_alive_at_stop": alive, "tcpsink": read_lines(f"{RUN}/tcpsink.jsonl"),
            "udpsink": read_lines(f"{RUN}/udpsink.jsonl"), "aqm": aqm, "guard": counters("j1249guard")}


def cmd_tcp_keys(count):
    """Make key pairs for `count` kernel WireGuard peers; returns [public, inner ip] each."""
    state["tcp_keys"] = [wg_key() for _ in range(count)]
    return {"peers": [[public, f"10.254.200.{i + 1}"] for i, (_, public) in enumerate(state["tcp_keys"])]}


def cmd_tcp_up(hub_public, hub_ip):
    """(Re)create one kernel WireGuard interface per TCP peer, fresh sessions, and prime each."""
    failed = []
    for i, (private, _) in enumerate(state["tcp_keys"]):
        dev, inner, table = f"wgt{i}", f"10.254.200.{i + 1}", str(100 + i)
        ns("ip", "link", "del", dev, check=False)
        ns("ip", "rule", "del", "from", inner, check=False)
        ns("ip", "link", "add", dev, "type", "wireguard")
        key = f"{RUN}/k{i}"
        with open(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(private + "\n")
        ns(f"{BIN}/wg", "set", dev, "private-key", key, "listen-port", str(40000 + i), "peer", hub_public,
           "endpoint", f"{hub_ip}:{WG_PORT}", "allowed-ips", f"{HUB_MESH}/32")
        os.unlink(key)
        ns("ip", "addr", "add", f"{inner}/32", "dev", dev)
        ns("ip", "link", "set", dev, "mtu", str(MTU), "up")
        ns("ip", "route", "add", HUB_MESH, "dev", dev, "table", table)
        ns("ip", "rule", "add", "from", inner, "lookup", table)
    for i in range(len(state["tcp_keys"])):
        ping = ns("ping", "-c", "1", "-W", "3", "-I", f"10.254.200.{i + 1}", HUB_MESH, check=False)
        if ping.returncode:
            failed.append(i)
    return {"unreachable": failed}


def cmd_tcp_load(bulk_peers, probe_peers, start, stop_at, until, interval_ms):
    """Run bulk uploads and probes; return each probe's round trips and the TCP retransmit count."""
    probes = []
    for i in probe_peers:
        inner = f"10.254.200.{i + 1}"
        probes.append(spawn(f"probe{i}", ["python3", "-I", f"{ROOT}/tcpload.py", "probe", inner, HUB_MESH,
                                          str(ECHO_PORT), str(start), str(stop_at), str(interval_ms)]))
    for i in bulk_peers:
        spawn(f"bulk{i}", ["python3", "-I", f"{ROOT}/tcpload.py", "bulk", f"10.254.200.{i + 1}", HUB_MESH,
                           str(BULK_PORT), str(until)])
    at(start)
    first = {"tcp": snmp(ns("cat", "/proc/net/snmp").stdout, "Tcp"), "cpus": per_cpu(), "t": time.time()}
    at(stop_at)
    last = {"tcp": snmp(ns("cat", "/proc/net/snmp").stdout, "Tcp"), "cpus": per_cpu(), "t": time.time()}
    results = []
    for child, i in zip(probes, probe_peers):
        try:
            child.wait(timeout=max(1, until + 15 - time.time()))
        except subprocess.TimeoutExpired:
            pass
        lines = read_lines(f"{RUN}/probe{i}.log")
        results.append({"peer": i, **lines[-1]} if lines else
                       {"peer": i, "error": open(f"{RUN}/probe{i}.err").read()[-300:]})
    at(until + 1)
    errors = {i: open(f"{RUN}/bulk{i}.err").read()[-300:] for i in bulk_peers
              if os.path.getsize(f"{RUN}/bulk{i}.err")}
    for i in bulk_peers:
        stop(f"bulk{i}")
    for i in probe_peers:
        stop(f"probe{i}")
    return {"probes": results, "first": first, "last": last, "bulk_errors": errors}


def cmd_sim_keys(instances):
    """Make keys for each flooding process ([count, id base]); returns [public, inner ip] pairs."""
    peers = []
    state["sims"] = instances
    for n, (count, base) in enumerate(instances):
        listing = f"{RUN}/peers{n}.json"
        sh(f"{BIN}/peersim", "keys", str(count), f"{RUN}/keys{n}.bin", listing, "single")
        os.chmod(f"{RUN}/keys{n}.bin", 0o600)
        with open(listing) as f:
            for entry in json.load(f):
                ident = base + entry["id"]
                public = base64.b64encode(bytes.fromhex(entry["key"])).decode()
                peers.append([public, f"10.254.{1 + ident // 256}.{ident % 256}"])
    return {"peers": peers}


def sim_command(n, text, wait):
    """Send one command line to flooding process `n` and wait for its result line."""
    sim = state["fifos"][n]
    before = len(read_lines(f"{RUN}/sim{n}.jsonl"))
    sim.write(text + "\n")
    sim.flush()
    deadline = time.time() + wait
    while time.time() < deadline:
        lines = read_lines(f"{RUN}/sim{n}.jsonl")
        if len(lines) > before:
            return lines[-1]
        if children[f"sim{n}"].poll() is not None:
            raise RuntimeError(f"peersim {n} exited: " + open(f"{RUN}/sim{n}.err").read()[-500:])
        # sleep: poll for the result line.
        time.sleep(0.1)
    raise RuntimeError(f"peersim {n} did not answer {text.split()[0]}")


def cmd_sim_start(hub_public, hub_ip, cpus):
    """Start one flooding process per instance on its own CPU and bring all its sessions up."""
    state["fifos"] = {}
    answers = []
    for n, (count, base) in enumerate(state["sims"]):
        fifo, out = f"{RUN}/fifo{n}", f"{RUN}/sim{n}.jsonl"
        for path in (fifo, out):
            if os.path.exists(path):
                os.unlink(path)
        os.mkfifo(fifo, 0o600)
        open(out, "w").close()
        spawn(f"sim{n}", [f"{BIN}/peersim", "sim", f"{RUN}/keys{n}.bin", fifo, out, hub_ip, str(WG_PORT), "single"],
              cpus=cpus[n], env={"PEERSIM_UNDERLAY": state["ip"], "PEERSIM_ID_BASE": str(base)})
        state["fifos"][n] = open(fifo, "w")
        sim_command(n, "identity " + base64.b64decode(hub_public).hex(), 10)
        answers.append(sim_command(n, f"connect {count} 0", 60))
    return {"connect": answers}


def cmd_sim_send(start, secs, senders, payload, mbit):
    """From `start`, flood for `secs` s: each process uses `senders[n]` peers at `mbit[n]` Mbit/s."""
    results = [None] * len(senders)
    failures = []

    def one(n):
        """Drive one flooding process."""
        try:
            results[n] = sim_command(n, f"send {senders[n]} {secs} {payload} {mbit[n]}", secs + 20)
        except Exception as error:  # reported to the driver below
            failures.append(str(error))

    at(start)
    first = {"cpus": per_cpu(), "t": time.time()}
    threads = [threading.Thread(target=one, args=(n,)) for n in range(len(senders))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if failures:
        raise RuntimeError("; ".join(failures))
    return {"send": results, "first": first, "last": {"cpus": per_cpu(), "t": time.time()}}


def cmd_sim_stop():
    """Stop every flooding process."""
    for n, fifo in state.pop("fifos", {}).items():
        try:
            fifo.close()
        except OSError:
            pass
        stop(f"sim{n}")
    return {}


def cmd_guard():
    """The namespace guard's drop counters."""
    return {"guard": counters("j1249guard")}


def teardown():
    """Remove every process, key file and the namespace. Safe to call more than once."""
    for name in list(children):
        stop(name)
    if os.path.exists(f"/run/netns/{NS}") and "ip" in state:
        for pid in sh("ip", "netns", "pids", NS, check=False).stdout.split():
            try:
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        sh("ip", "netns", "del", NS, check=False)
    sh("ip", "link", "del", LINK, check=False)
    try:
        os.unlink(f"/var/run/wireguard/{TUN}.sock")
    except FileNotFoundError:
        pass
    if os.path.isdir(RUN):
        for name in os.listdir(RUN):
            if name.startswith(("k", "fifo")):
                os.unlink(f"{RUN}/{name}")


def main():
    """Serve requests until stdin closes; always tear down."""
    def leave(signum, _frame):
        """Turn a signal into an exit so the `finally` below runs."""
        raise SystemExit(128 + signum)

    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, leave)
    try:
        while True:
            signal.alarm(900)
            line = sys.stdin.readline()
            if not line:
                break
            request = json.loads(line)
            name = request.pop("cmd")
            try:
                reply = {"ok": True, "result": globals()[f"cmd_{name}"](**request)}
            except subprocess.CalledProcessError as error:
                reply = {"ok": False, "error": f"{error}: {error.stderr}"}
            except Exception as error:  # every failure goes back to the driver
                reply = {"ok": False, "error": f"{type(error).__name__}: {error}"}
            print("J " + json.dumps(reply), flush=True)
    finally:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.alarm(0)
        teardown()


if __name__ == "__main__":
    main()
