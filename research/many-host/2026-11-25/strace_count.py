#!/usr/bin/env python3
"""Count SQLite-lock-wait evidence in a seccomp-bpf strace log, split by process.

Usage: strace_count.py STRACE_LOG RESULT_JSON

The log comes from `strace -f --seccomp-bpf -ttt -e trace=nanosleep,clock_nanosleep,
fsync,fdatasync` wrapped around the server test process. SQLite's busy handler
sleeps with nanosleep when another connection holds the write lock, so the number
of `nanosleep` calls on the server's threads is the number of lock waits and their
summed duration is the time spent waiting. `fsync`/`fdatasync` count WAL syncs.
RESULT_JSON is the driver's output; its `tids` field says which thread ids
belong to the server and which to the agents (threads that exited before the end
of the run are counted as `other`, mostly short-lived blocking-pool threads).
"""
import json, re, sys, collections

log, res = sys.argv[1], json.load(open(sys.argv[2]))
server, agents = set(res['tids']['server']), set(res['tids']['agents'])
line = re.compile(r'^(\d+)\s+\d+\.\d+\s+(\w+)\((.*?)\)\s+=\s+(-?\d+)\s*(?:<([\d.]+)>)?')
count = collections.Counter()
slept = collections.defaultdict(float)
for raw in open(log, errors='replace'):
    m = line.match(raw)
    if not m:
        continue
    tid, name = int(m.group(1)), m.group(2)
    who = 'server' if tid in server else 'agents' if tid in agents else 'other'
    count[(who, name)] += 1
    # nanosleep(&{tv_sec=0, tv_nsec=1000000}, ...) : sum the requested time
    r = re.search(r'tv_sec=(\d+), tv_nsec=(\d+)', m.group(3))
    if name in ('nanosleep', 'clock_nanosleep') and r:
        slept[who] += int(r.group(1)) + int(r.group(2)) / 1e9
out = {f'{w}.{n}': c for (w, n), c in sorted(count.items())}
out.update({f'{w}.sleep_s': round(v, 3) for w, v in slept.items()})
print(json.dumps(out))
