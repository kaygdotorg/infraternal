"""Turn the driver's per-point JSON (raw/*.raw, last line) into results.csv and a Markdown table.

Usage: python3 table.py raw/*.raw > results.md   (writes results.csv beside this file)
One row per run: runtime and round from the file name, then server CPU, the busiest server
thread, wakeups, RSS and the latency rows the D375 table asks for (J1246, #562).
"""
import csv, json, sys
from pathlib import Path

COLUMNS = ['runtime', 'round', 'hosts', 'term_per_host', 'server_cpu_idle_pct', 'server_cpu_typing_pct',
           'busiest_thread_idle_pct', 'busy_threads_idle', 'server_wakeups_idle_per_s', 'server_rss_mib',
           'others_cpu_idle_pct', 'key_p50_ms', 'key_p99_ms', 'key_max_ms', 'attach_p99_ms', 'reattach_p99_ms',
           'invitation_retries']
rows = []
for name in sys.argv[1:]:
    d = json.loads(Path(name).read_text().strip().splitlines()[-1])
    stem = Path(name).stem                       # e.g. production1-h200-t2
    tag = stem.split('-')[0]
    iv, ec = d['idle_view'], d['echo']
    rows.append(dict(
        runtime=tag.rstrip('0123456789'), round=tag[len(tag.rstrip('0123456789')):],
        hosts=d['hosts'], term_per_host=d['terminals']['per_host'],
        server_cpu_idle_pct=round(iv['server']['cpu_pct_core'], 1),
        server_cpu_typing_pct=round(ec['window']['server']['cpu_pct_core'], 1),
        busiest_thread_idle_pct=iv['server_thread_cpu']['busiest_pct'],
        busy_threads_idle=iv['server_thread_cpu']['busy_threads'],
        server_wakeups_idle_per_s=round(iv['server']['wakeups_per_s']),
        server_rss_mib=round(iv['server']['rss_mib'], 1),
        others_cpu_idle_pct=round(iv['agents']['cpu_pct_core'] + iv['below']['cpu_pct_core'], 1),
        key_p50_ms=round(ec['p50_ms'], 2), key_p99_ms=round(ec['p99_ms'], 2), key_max_ms=round(ec['max_ms'], 2),
        attach_p99_ms=round(d['terminals']['attach_p99_ms'], 1), reattach_p99_ms=round(d['reattach']['p99_ms'], 1),
        invitation_retries=d['enrol']['invitation_retries']))
rows.sort(key=lambda r: (-r['hosts'], r['runtime'], r['round']))
with open(Path(__file__).with_name('results.csv'), 'w', newline='') as f:
    w = csv.DictWriter(f, COLUMNS); w.writeheader(); w.writerows(rows)
print('| ' + ' | '.join(COLUMNS) + ' |')
print('|' + '---|' * len(COLUMNS))
for r in rows:
    print('| ' + ' | '.join(str(r[c]) for c in COLUMNS) + ' |')
