#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1239 (#260) queue sampler: where a loaded window's standing queue sits, on one VM.

J1230 saw CUBIC p99 grow with the number of receive lanes and blamed the `fq` flow allowance on
eth0. Every lane socket is also bound with the engine's forced 7 MiB SO_RCVBUF/SO_SNDBUF, so the
socket queues are a second suspect. This samples both, every <period> ms for <seconds> s:

- every UDP socket of the fixture netns (read from /proc/<pid>/net/udp of a process inside it, so
  no `ss` is spawned): local port, rx_queue and tx_queue bytes (rmem_alloc / wmem_alloc, skb
  truesize, the same budget SO_RCVBUF/SO_SNDBUF bound) and the socket's drop counter;
- the netns's Udp RcvbufErrors / SndbufErrors / InErrors and the TUN device's drop counters;
- eth0's root qdisc in the host netns (`tc -s qdisc`): backlog bytes and packets, drops,
  `flows_plimit` (fq's per-flow drops) and throttled.

Writes one JSON file: the samples and a summary (per socket and for eth0: mean, p50, p99 and max
of each queue, and the counter deltas over the run).

    qs.py <out.json> <seconds> <period-ms>
"""
import json
import os
import re
import subprocess
import sys
import time

NS = "j39"
TUN = "j39w"


def ns_pid():
    """Any process inside the fixture netns, to read its /proc/<pid>/net view."""
    pids = subprocess.run(["ip", "netns", "pids", NS], capture_output=True, text=True).stdout.split()
    for p in pids:
        if os.path.exists(f"/proc/{p}/net/udp"):
            return p
    return None


def udp_sockets(pid):
    """{local port: (rx_queue, tx_queue, drops)} for the netns's IPv4 and IPv6 UDP sockets."""
    out = {}
    for name in ("udp", "udp6"):
        try:
            lines = open(f"/proc/{pid}/net/{name}").read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            port = int(f[1].rsplit(":", 1)[1], 16)
            tx, rx = (int(v, 16) for v in f[4].split(":"))
            drops = int(f[-1])
            key = f"{name}:{port}"
            out[key] = (rx, tx, drops)
    return out


def snmp(pid):
    """The netns's Udp counters we care about."""
    want = ("InErrors", "RcvbufErrors", "SndbufErrors")
    try:
        lines = [l.split() for l in open(f"/proc/{pid}/net/snmp") if l.startswith("Udp:")]
    except OSError:
        return {}
    head, vals = lines[0][1:], lines[1][1:]
    return {k: int(v) for k, v in zip(head, vals) if k in want}


def tun_drops(pid):
    """rx/tx drop counters of the tunnel device, from the netns's /proc/net/dev."""
    try:
        for line in open(f"/proc/{pid}/net/dev"):
            if line.strip().startswith(TUN + ":"):
                f = line.split(":", 1)[1].split()
                return {"rx_drop": int(f[3]), "tx_drop": int(f[11])}
    except OSError:
        pass
    return {}


QDISC_RE = {
    "backlog_b": re.compile(r"backlog (\d+)b"),
    "backlog_p": re.compile(r"backlog \d+b (\d+)p"),
    "drops": re.compile(r"dropped (\d+)"),
    "flows_plimit": re.compile(r"flows_plimit (\d+)"),
    "throttled": re.compile(r"(\d+) throttled"),
}


def qdisc():
    """eth0's root qdisc counters (host netns)."""
    text = subprocess.run(["tc", "-s", "qdisc", "show", "dev", "eth0"], capture_output=True, text=True).stdout
    root = text.split("\nqdisc ", 1)[0]
    out = {}
    for k, rx in QDISC_RE.items():
        m = rx.search(root)
        if m:
            out[k] = int(m.group(1))
    return out


def stats(values):
    """mean, p50, p99 and max of a list of numbers (nearest rank)."""
    if not values:
        return {}
    v = sorted(values)
    rank = lambda q: v[min(len(v) - 1, max(0, int(round(q * len(v) + 0.5)) - 1))]
    return {"mean": round(sum(v) / len(v)), "p50": rank(0.50), "p99": rank(0.99), "max": v[-1]}


def main():
    out, seconds, period = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]) / 1000
    pid = ns_pid()
    samples = []
    end = time.monotonic() + seconds
    next_t = time.monotonic()
    while time.monotonic() < end and pid:
        samples.append({"t": time.monotonic(), "udp": udp_sockets(pid), "snmp": snmp(pid),
                        "tun": tun_drops(pid), "qdisc": qdisc()})
        next_t += period
        # sleep: the sampling period.
        time.sleep(max(0.0, next_t - time.monotonic()))
    summary = {"n": len(samples)}
    if samples:
        first, last = samples[0], samples[-1]
        socks = {}
        for key in last["udp"]:
            rx = [s["udp"][key][0] for s in samples if key in s["udp"]]
            tx = [s["udp"][key][1] for s in samples if key in s["udp"]]
            d0 = first["udp"].get(key, (0, 0, last["udp"][key][2]))[2]
            socks[key] = {"rx": stats(rx), "tx": stats(tx), "drops": last["udp"][key][2] - d0}
        # Sum over the engine's sockets at each instant: the peer's total socket queue.
        total_rx = [sum(v[0] for v in s["udp"].values()) for s in samples]
        total_tx = [sum(v[1] for v in s["udp"].values()) for s in samples]
        summary.update(
            sockets=socks, total_rx=stats(total_rx), total_tx=stats(total_tx),
            snmp={k: last["snmp"].get(k, 0) - first["snmp"].get(k, 0) for k in last["snmp"]},
            tun={k: last["tun"].get(k, 0) - first["tun"].get(k, 0) for k in last["tun"]},
            qdisc_backlog_b=stats([s["qdisc"].get("backlog_b", 0) for s in samples]),
            qdisc_backlog_p=stats([s["qdisc"].get("backlog_p", 0) for s in samples]),
            qdisc={k: last["qdisc"].get(k, 0) - first["qdisc"].get(k, 0)
                   for k in ("drops", "flows_plimit", "throttled")},
        )
    with open(out, "w") as f:
        json.dump({"summary": summary, "samples": samples}, f)


if __name__ == "__main__":
    main()
