#!/usr/bin/env python3
"""GotaTun loss-control overload latch, TCP and UDP (#260, J1241). Run as root under `perf-run --root`.

Builds two network namespaces joined by a veth pair (10.231.0.0/24, no default route, nothing in the
host namespace). In the hub namespace it runs the GotaTun CLI (the engine, with the AQM under test,
`GOTATUN_AQM`) and one `iperf3 -s` per simulated peer. In the other namespace it creates K kernel
WireGuard interfaces, one per simulated peer (own key, own inner address, own UDP source port), and
drives them with one `iperf3` client each (policy routing sends each client through its own
interface). Everything is removed in a `finally`/signal handler.

Phases (each `--secs` long, flows start together):
  base      10 flows, paced at --rate Mbit/s each                (reference)
  overload  --flows flows, unpaced for TCP / --udp-rate for UDP  (push the hub past what it can take)
  post1     as base, started 1 s after overload ends            (does the engine recover at once?)
  post2     as base, after 5 s of idle                          (does it recover with time?)
  single    1 unpaced flow                                       (headroom left after the episode)
  base2     as base, after another 10 s idle

Output: `<out>/<tag>.csv` (one row per phase) and `<out>/<tag>.aqm.<pid>` (the engine's per-period AQM
counter lines, when --aqm-stats-ms is set) plus the raw iperf3 JSON under `<out>/<tag>.json/`.

usage: run.py --hub 'GOTATUN [ARGS]' --iperf IPERF3 --wg WG --out DIR --tag TAG
              [--proto tcp|udp] [--aqm ecn|drop|off|default] [--tcp-ecn 0|1] [--flows 100]
"""
import argparse, base64, csv, json, os, shlex, signal, subprocess, sys, time

NS_HUB, NS_SIM = "hub1241", "sim1241"
TICK = os.sysconf("SC_CLK_TCK")
HUB_IP, VETH_HUB, VETH_SIM = "10.232.0.1", "10.231.0.1", "10.231.0.2"
IF_HUB = "wgh1241"


def sh(*args, check=True, **kw):
    return subprocess.run(args, check=check, **kw)


def run_out(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def cpu_s(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / TICK


def ns_stat(ns, dev, name):
    return int(run_out("ip", "netns", "exec", ns, "cat", f"/sys/class/net/{dev}/statistics/{name}"))


def hexkey(b64):
    return base64.b64decode(b64).hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", required=True, help="gotatun command line prefix (loader and binary)")
    ap.add_argument("--iperf", required=True)
    ap.add_argument("--wg", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--aqm", default="default", help="GOTATUN_AQM value, or 'default' to leave it unset")
    ap.add_argument("--aqm-env", action="append", default=[], help="extra KEY=VAL for the hub")
    ap.add_argument("--aqm-stats-ms", type=int, default=0)
    ap.add_argument("--tcp-ecn", default="0", help="net.ipv4.tcp_ecn in the client namespace")
    ap.add_argument("--flows", type=int, default=100)
    ap.add_argument("--base-flows", type=int, default=10)
    ap.add_argument("--rate", type=float, default=39.0, help="per-flow Mbit/s for the paced phases")
    ap.add_argument("--udp-rate", type=float, default=22.0, help="per-flow Mbit/s of the UDP overload phase")
    ap.add_argument("--secs", type=int, default=10)
    ap.add_argument("--hub-cpus", default="1")
    ap.add_argument("--server-cpus", default="2")
    ap.add_argument("--client-cpus", default="3")
    ap.add_argument("--phases", default="base,overload,post1,post2,single,base2")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    jdir = os.path.join(args.out, f"{args.tag}.json")
    os.makedirs(jdir, exist_ok=True)
    K = args.flows
    children = []

    def cleanup(*_):
        for p in children:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        for ns in (NS_HUB, NS_SIM):
            sh("ip", "netns", "del", ns, check=False, stderr=subprocess.DEVNULL)
        try:
            os.unlink(f"/var/run/wireguard/{IF_HUB}.sock")
        except FileNotFoundError:
            pass

    signal.signal(signal.SIGTERM, lambda *_: (cleanup(), sys.exit(143)))
    signal.signal(signal.SIGINT, lambda *_: (cleanup(), sys.exit(130)))
    rows = []
    try:
        for ns in (NS_HUB, NS_SIM):
            sh("ip", "netns", "del", ns, check=False, stderr=subprocess.DEVNULL)
            sh("ip", "netns", "add", ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")
        sh("ip", "link", "add", "vh1241", "type", "veth", "peer", "name", "vs1241")
        sh("ip", "link", "set", "vh1241", "netns", NS_HUB)
        sh("ip", "link", "set", "vs1241", "netns", NS_SIM)
        for ns, dev, ip in ((NS_HUB, "vh1241", VETH_HUB), (NS_SIM, "vs1241", VETH_SIM)):
            sh("ip", "-n", ns, "addr", "add", f"{ip}/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
        sh("ip", "netns", "exec", NS_SIM, "sysctl", "-qw", f"net.ipv4.tcp_ecn={args.tcp_ecn}")
        sh("ip", "netns", "exec", NS_HUB, "sysctl", "-qw", f"net.ipv4.tcp_ecn={args.tcp_ecn}")

        # Keys: one hub key pair, K peer key pairs.
        hub_priv = run_out(args.wg, "genkey")
        hub_pub = subprocess.run([args.wg, "pubkey"], input=hub_priv, capture_output=True, text=True, check=True).stdout.strip()
        peers = []
        for k in range(K):
            priv = run_out(args.wg, "genkey")
            pub = subprocess.run([args.wg, "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
            peers.append((priv, pub, f"10.232.{k // 200}.{10 + k % 200}"))

        # Hub engine.
        env = dict(os.environ)
        if args.aqm != "default":
            env["GOTATUN_AQM"] = args.aqm
        if args.aqm_stats_ms:
            env["GOTATUN_AQM_STATS_MS"] = str(args.aqm_stats_ms)
            env["GOTATUN_AQM_STATS_PATH"] = os.path.join(args.out, f"{args.tag}.aqm")
        for kv in args.aqm_env:
            key, val = kv.split("=", 1)
            env[key] = val
        hubcmd = ["ip", "netns", "exec", NS_HUB, "taskset", "-c", args.hub_cpus, *shlex.split(args.hub),
                  "-f", "--disable-drop-privileges", "-l", os.path.join(args.out, f"{args.tag}.hub.log"), IF_HUB]
        hub = subprocess.Popen(hubcmd, env=env, start_new_session=True, stdout=subprocess.DEVNULL, stderr=open(os.path.join(args.out, f"{args.tag}.hub.err"), "w"))
        children.append(hub)
        sock = f"/var/run/wireguard/{IF_HUB}.sock"
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        else:
            raise SystemExit("hub UAPI socket did not appear")
        # `ip netns exec`, `taskset` and the loader all exec, so the Popen pid is the engine's pid.
        hub_pid = hub.pid
        # Configure through UAPI (hex keys), one peer per simulated host.
        cfg = f"set=1\nprivate_key={hexkey(hub_priv)}\nlisten_port=51820\nreplace_peers=true\n"
        for priv, pub, ip in peers:
            cfg += f"public_key={hexkey(pub)}\nreplace_allowed_ips=true\nallowed_ip={ip}/32\n"
        cfg += "\n"
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock)
        s.sendall(cfg.encode())
        reply = s.recv(4096).decode()
        s.close()
        if "errno=0" not in reply:
            raise SystemExit(f"UAPI set failed: {reply!r}")
        sh("ip", "-n", NS_HUB, "addr", "add", f"{HUB_IP}/16", "dev", IF_HUB)
        sh("ip", "-n", NS_HUB, "link", "set", IF_HUB, "mtu", "1420", "up")

        # Simulated peers: one kernel WireGuard interface each.
        for k, (priv, pub, ip) in enumerate(peers):
            dev = f"wgp{k}"
            sh("ip", "-n", NS_SIM, "link", "add", dev, "type", "wireguard")
            keyfile = os.path.join(args.out, f".k{k}.key")
            with open(keyfile, "w") as f:
                os.chmod(keyfile, 0o600)
                f.write(priv + "\n")
            sh("ip", "netns", "exec", NS_SIM, args.wg, "set", dev, "private-key", keyfile, "listen-port", str(40000 + k),
               "peer", hub_pub, "endpoint", f"{VETH_HUB}:51820", "allowed-ips", f"{HUB_IP}/32")
            os.unlink(keyfile)
            sh("ip", "-n", NS_SIM, "addr", "add", f"{ip}/32", "dev", dev)
            sh("ip", "-n", NS_SIM, "link", "set", dev, "mtu", "1420", "up")
            sh("ip", "-n", NS_SIM, "route", "add", HUB_IP, "dev", dev, "table", str(100 + k))
            sh("ip", "-n", NS_SIM, "rule", "add", "from", ip, "lookup", str(100 + k))

        # One iperf3 server per peer, on the hub's own inner address.
        for k in range(K):
            p = subprocess.Popen(["ip", "netns", "exec", NS_HUB, "taskset", "-c", args.server_cpus, args.iperf, "-s",
                                  "-B", HUB_IP, "-p", str(5200 + k)], start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(p)
        time.sleep(0.5)
        # Prime every session so no phase pays a handshake (1 ping each).
        for k, (priv, pub, ip) in enumerate(peers):
            sh("ip", "netns", "exec", NS_SIM, "ping", "-c", "1", "-W", "2", "-I", ip, HUB_IP, stdout=subprocess.DEVNULL, check=False)

        def phase(name, nflows, rate_mbit, secs):
            """Run nflows clients for secs; return the measured row."""
            procs = []
            t0_wall = time.time()
            rx0 = ns_stat(NS_HUB, IF_HUB, "rx_bytes")  # bytes the engine delivered to the kernel
            cpu0 = cpu_s(hub_pid)
            for k in range(nflows):
                cmd = ["ip", "netns", "exec", NS_SIM, "taskset", "-c", args.client_cpus, args.iperf, "-c", HUB_IP, "-B", peers[k][2],
                       "-p", str(5200 + k), "-t", str(secs), "-J", "--connect-timeout", "3000"]
                if args.proto == "udp":
                    cmd += ["-u", "-b", f"{rate_mbit}M", "-l", "1380"]
                elif rate_mbit:
                    cmd += ["-b", f"{rate_mbit}M"]
                out = open(os.path.join(jdir, f"{name}-{k}.json"), "w")
                procs.append((subprocess.Popen(cmd, stdout=out, stderr=subprocess.DEVNULL, start_new_session=True), out))
            for p, out in procs:
                children.append(p)
            t_end = time.time() + secs + 15
            for p, out in procs:
                try:
                    p.wait(timeout=max(1, t_end - time.time()))
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                out.close()
            t1_wall = time.time()
            rx1 = ns_stat(NS_HUB, IF_HUB, "rx_bytes")
            cpu1 = cpu_s(hub_pid)
            recv = sent = retr = 0.0
            lost = pkts = 0
            ok = 0
            for k in range(nflows):
                try:
                    j = json.load(open(os.path.join(jdir, f"{name}-{k}.json")))
                    e = j["end"]
                except Exception:
                    continue
                if ("sum_received" if args.proto == "tcp" else "sum") not in e:
                    continue
                ok += 1
                if args.proto == "tcp":
                    recv += e["sum_received"]["bits_per_second"]
                    sent += e["sum_sent"]["bits_per_second"]
                    retr += e["sum_sent"].get("retransmits", 0)
                else:
                    sent += e["sum"]["bits_per_second"]
                    lost += e["sum"].get("lost_packets", 0)
                    pkts += e["sum"].get("packets", 0)
                    recv += e["sum"]["bits_per_second"] * (1 - e["sum"].get("lost_percent", 0) / 100)
            wall = t1_wall - t0_wall
            row = dict(tag=args.tag, phase=name, flows=nflows, ok=ok, t_start=round(t0_wall, 3), t_end=round(t1_wall, 3),
                       wall_s=round(wall, 2), recv_mbit=round(recv / 1e6, 1), sent_mbit=round(sent / 1e6, 1),
                       tun_mbit=round((rx1 - rx0) * 8 / wall / 1e6, 1), retrans=int(retr),
                       udp_lost_pct=round(100 * lost / pkts, 2) if pkts else "",
                       hub_cpu_s=round(cpu1 - cpu0, 2))
            rows.append(row)
            print(json.dumps(row), flush=True)

        want = args.phases.split(",")
        for name in want:
            if name == "base":
                phase("base", args.base_flows, args.rate, args.secs)
            elif name == "overload":
                phase("overload", args.flows, args.udp_rate if args.proto == "udp" else 0, args.secs)
            elif name == "post1":
                time.sleep(1)
                phase("post1", args.base_flows, args.rate, args.secs)
            elif name == "post2":
                time.sleep(5)
                phase("post2", args.base_flows, args.rate, args.secs)
            elif name == "single":
                time.sleep(2)
                phase("single", 1, args.udp_rate * 20 if args.proto == "udp" else 0, args.secs)
            elif name == "base2":
                time.sleep(10)
                phase("base2", args.base_flows, args.rate, args.secs)
    finally:
        cleanup()
        if rows:
            with open(os.path.join(args.out, f"{args.tag}.csv"), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)


if __name__ == "__main__":
    main()
