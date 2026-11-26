#!/usr/bin/env python3
"""Flatten the matrix JSON lines into one CSV row per (hosts, terminals per host) point.

Usage: to_csv.py OUT_DIR > results.csv   (reads OUT_DIR/*.jsonl and OUT_DIR/*.strace.json)
Times are milliseconds, CPU is percent of one core, memory is MiB.
"""
import csv, glob, json, os, sys

out = sys.argv[1]
rows = []
for f in sorted(glob.glob(os.path.join(out, '*.jsonl'))):
    for line in open(f):
        d = json.loads(line)
        if d.get('failed') or 'terminals' not in d:
            rows.append(dict(set=d.get('set'), hosts=d.get('H'), terminals_per_host=d.get('T'), rc=d.get('rc'), failed=1))
            continue
        t, e, w, iv, ob = d['terminals'], d['echo'], d['echo']['window'], d['idle_view'], d['idle_bare']
        sj = os.path.join(out, f"{d['set']}-h{d['H']}-t{d['T']}.strace.json")
        sc = json.load(open(sj)) if os.path.exists(sj) else {}
        rows.append(dict(
            set=d['set'], hosts=d['H'], terminals_per_host=d['T'], terminals_opened=t['opened'], memory_capped=int(t['memory_capped']), rc=d['rc'],
            enrol_total_s=round(d['enrol']['total_s'], 2), enrol_p99_ms=round(d['enrol']['p99_ms'], 1),
            idle_bare_server_cpu=round(ob['server']['cpu_pct_core'], 2), idle_bare_server_wake_s=round(ob['server']['wakeups_per_s'], 1),
            idle_bare_agents_cpu=round(ob['agents']['cpu_pct_core'], 2),
            server_rss_mib_end=round(d['end']['server']['rss_kb'] / 1024, 1), server_anon_mib_end=round(d['end']['server']['anon_kb'] / 1024, 1),
            server_threads=d['end']['server']['threads'], server_fds=d['end']['server']['fds'],
            agents_rss_mib_end=round(d['end']['agents_rss_mib'], 1), cgroup_mem_mib_end=round(d['end']['cgroup_mem_mib'], 1),
            below_n=d.get('below_detail', {}).get('n'), below_anon_mib=round(d.get('below_detail', {}).get('anon_mib', 0), 1),
            open_wall_s=round(t['wall_s'], 2), opens_per_s=round(t['opens_per_s'], 1), refused_retries=t['refused_retries'],
            open_p50_ms=round(t['open_p50_ms'], 1), open_p99_ms=round(t['open_p99_ms'], 1),
            attach_p50_ms=round(t['attach_p50_ms'], 1), attach_p99_ms=round(t['attach_p99_ms'], 1),
            open_server_cpu=round(t['during']['server']['cpu_pct_core'], 1),
            idle_view_server_cpu=round(iv['server']['cpu_pct_core'], 2), idle_view_server_wake_s=round(iv['server']['wakeups_per_s'], 0),
            idle_view_agents_cpu=round(iv['agents']['cpu_pct_core'], 2), idle_view_shims_cpu=round(iv['below']['cpu_pct_core'], 2),
            frames_to_viewers_s=iv.get('frames_to_viewers_per_s'),
            key_typists=e['typists'], key_keys=e['keys'], key_p50_ms=round(e['p50_ms'], 2), key_p90_ms=round(e['p90_ms'], 2),
            key_p99_ms=round(e['p99_ms'], 2), key_max_ms=round(e['max_ms'], 2), key_server_cpu=round(w['server']['cpu_pct_core'], 1),
            key_one_p50_ms=round(d['echo_one']['p50_ms'], 2), key_one_p99_ms=round(d['echo_one']['p99_ms'], 2),
            reattach_n=d['reattach']['n'], reattach_p50_ms=round(d['reattach']['p50_ms'], 1), reattach_p99_ms=round(d['reattach']['p99_ms'], 1),
            lock_waits_server=sc.get('server.nanosleep', 0) + sc.get('server.clock_nanosleep', 0) if sc else '',
            lock_sleep_s_server=sc.get('server.sleep_s', 0) if sc else '',
            fsyncs_server=sc.get('server.fsync', 0) + sc.get('server.fdatasync', 0) if sc else ''))
# A point retried after a harness fix keeps its good row; a failed row is kept only when nothing succeeded.
best = {}
for r in rows:
    k = (r['set'], r['hosts'], r['terminals_per_host'])
    if k not in best or (best[k].get('failed') and not r.get('failed')):
        best[k] = r
rows = sorted(best.values(), key=lambda r: (r['set'], r['hosts'], r['terminals_per_host']))
cols = []
for r in rows:
    for k in r:
        if k not in cols:
            cols.append(k)
w = csv.DictWriter(sys.stdout, fieldnames=cols)
w.writeheader()
w.writerows(rows)
