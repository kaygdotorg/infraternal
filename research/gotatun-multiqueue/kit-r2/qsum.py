#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1239 (#260) summarize qs.py's queue samples of a hold into one CSV, one line per window and VM.

Columns: hold, row, window, vm, the engine sockets' summed rx queue (mean/p99/max KiB) and tx
queue (mean/p99/max KiB), the largest single socket's rx p99 (KiB), socket drops, the netns's UDP
RcvbufErrors/SndbufErrors, TUN rx/tx drops, eth0's fq backlog (mean/p99 packets) and its drops
and flows_plimit drops over the 40 s steady window.

    qsum.py <raw-dir> <hold>... > OUT.csv
"""
import csv
import json
import os
import sys

COLS = ["hold", "row", "window", "vm", "rx_mean_kib", "rx_p99_kib", "rx_max_kib", "tx_mean_kib",
        "tx_p99_kib", "tx_max_kib", "rx_p99_top_socket_kib", "sock_drops", "rcvbuf_err", "sndbuf_err",
        "tun_rx_drop", "tun_tx_drop", "fq_backlog_mean_p", "fq_backlog_p99_p", "fq_drops", "fq_plimit"]


def kib(v):
    """Bytes to KiB, rounded."""
    return round(v / 1024) if isinstance(v, (int, float)) else ""


def main():
    raw, holds = sys.argv[1], sys.argv[2:]
    w = csv.DictWriter(sys.stdout, COLS)
    w.writeheader()
    for hold in holds:
        for vm in ("a", "b"):
            base = os.path.join(raw, hold, vm, hold)
            if not os.path.isdir(base):
                continue
            for row in sorted(os.listdir(base)):
                rdir = os.path.join(base, row)
                if not os.path.isdir(rdir):
                    continue
                for win in sorted(os.listdir(rdir)):
                    p = os.path.join(rdir, win, "qs.json")
                    if not os.path.exists(p):
                        continue
                    s = json.load(open(p))["summary"]
                    if not s.get("n"):
                        continue
                    # Engine sockets only: the WireGuard ports (51820 + lane), not iperf3/rr.
                    socks = {k: v for k, v in s["sockets"].items() if 51820 <= int(k.split(":")[1]) < 51830}
                    top = max((v["rx"].get("p99", 0) for v in socks.values()), default=0)
                    w.writerow({
                        "hold": hold, "row": row, "window": win, "vm": vm,
                        "rx_mean_kib": kib(s["total_rx"]["mean"]), "rx_p99_kib": kib(s["total_rx"]["p99"]),
                        "rx_max_kib": kib(s["total_rx"]["max"]), "tx_mean_kib": kib(s["total_tx"]["mean"]),
                        "tx_p99_kib": kib(s["total_tx"]["p99"]), "tx_max_kib": kib(s["total_tx"]["max"]),
                        "rx_p99_top_socket_kib": kib(top),
                        "sock_drops": sum(v["drops"] for v in socks.values()),
                        "rcvbuf_err": s["snmp"].get("RcvbufErrors", ""), "sndbuf_err": s["snmp"].get("SndbufErrors", ""),
                        "tun_rx_drop": s["tun"].get("rx_drop", ""), "tun_tx_drop": s["tun"].get("tx_drop", ""),
                        "fq_backlog_mean_p": s["qdisc_backlog_p"].get("mean", ""),
                        "fq_backlog_p99_p": s["qdisc_backlog_p"].get("p99", ""),
                        "fq_drops": s["qdisc"].get("drops", ""), "fq_plimit": s["qdisc"].get("flows_plimit", ""),
                    })


if __name__ == "__main__":
    main()
