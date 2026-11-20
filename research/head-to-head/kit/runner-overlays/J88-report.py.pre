#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Turn one head-to-head results directory into summary.md (#260).

Reads the per-measurement JSON files the cases wrote and prints Markdown
tables. A missing cell means the measurement did not run or failed; its
.failed/.err file sits next to where the JSON would be.
"""
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])


def load(case, name):
    path = root / case / f"{name}.json"
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def get(value, *keys):
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def fmt(value, digits=2):
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def pair(summary, scale=1.0, digits=2):
    if not summary or summary.get("n", 0) == 0:
        return "–"
    return f"{summary['p50'] * scale:.{digits}f} / {summary['p99'] * scale:.{digits}f}"


env = json.loads((root / "environment.json").read_text())
print(f"# Head-to-head results: {env['label']}\n")
print(f"{env['host']} · {env['os']} · kernel {env['kernel']} · {env['cpu']} · {env['cores']} cores · "
      f"{env['mem_kb'] // 1024} MiB · load at start {' '.join(env['load'])}\n")
statuses = sorted(root.glob("*/status.json"))
print("| case | exit | seconds | machine diff |\n|---|---|---|---|")
for status in statuses:
    s = json.loads(status.read_text())
    diff = (status.parent / "machine-diff.txt")
    empty = diff.exists() and diff.stat().st_size == 0
    print(f"| {s['case']} | {s['exit']} | {s['seconds']} | {'empty' if empty else 'NOT EMPTY'} |")

failures = sorted(root.glob("*/*.failed"))
if failures:
    print("\nFailed measurements (error files are retained beside them):\n")
    for failure in failures:
        print(f"- `{failure.relative_to(root)}`")

systems = ["underlay", "infraternal", "tailscale", "gotatun", "boringtun", "wireguard-go", "netbird", "netbird-userspace"]
mesh = [s for s in systems if (root / f"mesh-{s}").is_dir()]
if mesh:
    print("\n## Mesh data plane (a → b, two namespaces, one machine)\n")
    print("| system | first packet ms | 1 flow Gbit/s | 8 flows Gbit/s | CPU s per Gbit (1 / 8) | idle CPU % | RSS idle MiB | RSS peak MiB |")
    print("|---|---|---|---|---|---|---|---|")
    for s in mesh:
        c = f"mesh-{s}"
        t1, t8, idle = load(c, "tput-lan-1"), load(c, "tput-lan-8"), load(c, "idle")
        rss_idle = get(idle, "mem", "rss_kb")
        peak = max(get(t1, "watched_rss_kb_peak") or 0, get(t8, "watched_rss_kb_peak") or 0)
        print(f"| {s} | {fmt(get(load(c, 'first-packet'), 'elapsed_ms'), 0)} | {fmt(get(t1, 'gbit_per_s'))} | "
              f"{fmt(get(t8, 'gbit_per_s'))} | {fmt(get(t1, 'machine_cpu_s_per_gbit'))} / {fmt(get(t8, 'machine_cpu_s_per_gbit'))} | "
              f"{fmt(get(idle, 'cpu_percent_of_one_core'), 3)} | {fmt(rss_idle / 1024 if rss_idle else None, 1)} | "
              f"{fmt(peak / 1024 if peak else None, 1)} |")
    print("\n## Peer-state memory (RSS is summed across both endpoints)\n")
    print("| system | RSS at 1 peer per endpoint MiB | RSS at 1,000 peers per endpoint MiB |")
    print("|---|---:|---:|")
    for s in ("infraternal", "tailscale", "gotatun", "boringtun", "wireguard-go"):
        if s not in mesh:
            continue
        c = f"mesh-{s}"
        one = get(load(c, "idle"), "mem", "rss_kb")
        thousand = get(load(c, "mem-1000"), "rss_kb")
        print(f"| {s} | {fmt(one / 1024 if one else None, 1)} | {fmt(thousand / 1024 if thousand else None, 1)} |")

    for tag, title in (("lan", "LAN"), ("de-in", "DE↔IN, 198 ms RTT netem"),
                       ("de-in-loss", "198 ms RTT, independent 2% loss per direction")):
        print(f"\n### Latency, {title}: p50 / p99 ms\n")
        print("| system | RTT 64 B | RTT 512 B | RTT 1400 B | one-way 64 B | one-way 1400 B | loss (64/512/1400) |")
        print("|---|---|---|---|---|---|---|")
        for s in mesh:
            c = f"mesh-{s}"
            l = {size: load(c, f"lat-{tag}-{size}") for size in (64, 512, 1400)}
            lost = "/".join(fmt((v or {}).get("sent", 0) - (v or {}).get("received", 0)) if v else "–" for v in l.values())
            print(f"| {s} | {pair(get(l[64], 'rtt_ms'), digits=3)} | {pair(get(l[512], 'rtt_ms'), digits=3)} | "
                  f"{pair(get(l[1400], 'rtt_ms'), digits=3)} | {pair(get(l[64], 'one_way_fwd_ms'), digits=3)} | "
                  f"{pair(get(l[1400], 'one_way_fwd_ms'), digits=3)} | {lost} |")
        print("\n| system | RTT 64 B under 1 flow p50 / p99 ms | RTT 64 B under 8 flows p50 / p99 ms |")
        print("|---|---|---|")
        for s in mesh:
            c = f"mesh-{s}"
            l1 = load(c, f"lat-load-{tag}-64-1")
            l8 = load(c, f"lat-load-{tag}-64-8")
            print(f"| {s} | {pair(get(l1, 'rtt_ms'), digits=3)} | {pair(get(l8, 'rtt_ms'), digits=3)} |")
        if tag != "lan":
            print("\n| system | 1 flow Gbit/s | 8 flows Gbit/s |\n|---|---|---|")
            for s in mesh:
                c = f"mesh-{s}"
                print(f"| {s} | {fmt(get(load(c, f'tput-{tag}-1'), 'gbit_per_s'), 3)} | {fmt(get(load(c, f'tput-{tag}-8'), 'gbit_per_s'), 3)} |")

viewers = ["ix", "tmux", "zellij", "tmux-ssh", "zellij-ssh", "ssh"]
names = {"ix": "infraternal", "tmux": "tmux", "zellij": "Zellij", "tmux-ssh": "tmux over SSH",
         "zellij-ssh": "Zellij over SSH", "ssh": "plain SSH (no multiplexer)"}
for profile, title in (("local", "local viewer"), ("wan", "150 ms one-way (300 ms RTT)"), ("loss", "150 ms one-way + 2 % loss")):
    c = f"term-{profile}"
    if not (root / c).is_dir():
        continue
    print(f"\n## Terminal, {title}\n")
    print("| viewer | echo p50 / p99 ms | cat 100 MB: s to marker at viewer | bytes to viewer | yes 10 s: lag s | reattach p50 / p99 ms |")
    print("|---|---|---|---|---|---|")
    for v in viewers:
        e = load(c, f"echo-{v}")
        failed_viewer = any((root / c).glob(f"*-{v}.json.failed"))
        if e is None and load(c, f"cat100mb-{v}") is None and not failed_viewer:
            continue
        cat, yes, att = load(c, f"cat100mb-{v}"), load(c, f"yes10s-{v}"), load(c, f"attach-{v}")
        lag = get(yes, "seconds_to_marker")
        print(f"| {names[v]} | {pair(get(e, 'echo_ms'))} | {fmt(get(cat, 'seconds_to_marker'))} | "
              f"{fmt(get(cat, 'bytes_delivered'))} | {fmt(lag - 10 if lag is not None else None)} | {pair(get(att, 'attach_ms'))} |")

c = "term-scale"
if (root / c).is_dir():
    print("\n## Terminal sessions at scale (host side; shells counted separately)\n")
    print("| system | PSS MiB at 1 / 10 / 50 | per extra session MiB (1→50) | RSS MiB at 50 | shells PSS MiB at 50 | idle CPU % detached / 1 viewer | viewer keepalives /s |")
    print("|---|---|---|---|---|---|---|")
    for v in ("ix", "tmux", "zellij"):
        pss = {n: get(load(c, f"mem-{v}-{n}"), "pss_kb") for n in (1, 10, 50)}
        rss50 = get(load(c, f"mem-{v}-50"), "rss_kb")
        per = (pss[50] - pss[1]) / 49 / 1024 if pss[50] and pss[1] else None
        det = get(load(c, f"idle-detached-{v}"), "cpu_percent_of_one_core")
        att = get(load(c, f"idle-attached-{v}"), "cpu_percent_of_one_core")
        keep = get(load(c, f"viewer-{v}"), "keepalive_probes_per_s")
        shells = get(load(c, f"shells-{v}-50"), "pss_kb")
        print(f"| {names[v]} | {' / '.join(fmt(pss[n] / 1024 if pss[n] else None, 1) for n in (1, 10, 50))} | {fmt(per)} | "
              f"{fmt(rss50 / 1024 if rss50 else None, 1)} | {fmt(shells / 1024 if shells is not None else None, 1)} | "
              f"{fmt(det, 3)} / {fmt(att, 3)} | {fmt(keep, 1)} |")
