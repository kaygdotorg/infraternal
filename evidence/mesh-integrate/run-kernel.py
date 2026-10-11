#!/usr/bin/env python3
"""Run every ignored Mesh regression in its own namespace and weighted scope."""
import json, os, subprocess
from pathlib import Path
scratch=Path('/home/kayg/.cache/codex-scratch/mesh-integrate')
artifacts=[]
for line in (scratch/'mesh-artifacts.jsonl').read_text().splitlines():
 try: row=json.loads(line)
 except json.JSONDecodeError: continue
 if row.get('reason')=='compiler-artifact' and row.get('executable') and row.get('profile',{}).get('test'):
  artifacts.append((row['target']['name'],row['executable']))
results=[]
for name,binary in artifacts:
 if name=='review_shutdown_budget': continue
 listed=subprocess.check_output([binary,'--list','--ignored'],text=True)
 for line in listed.splitlines():
  if not line.endswith(': test'): continue
  case=line.removesuffix(': test')
  if case=='crash_child': continue
  load=Path('/proc/loadavg').read_text().strip()
  log=scratch/(name+'-'+case.replace('::','-')+'.log')
  with log.open('w') as out:
   out.write('LOAD_START '+load+'\n');out.flush()
   result=subprocess.run(['systemd-run','--user','--scope','-p','CPUWeight=10000','unshare','-Urn',binary,'--ignored','--exact',case,'--nocapture','--test-threads=1'],stdout=out,stderr=subprocess.STDOUT,env=os.environ)
   out.write('LOAD_END '+Path('/proc/loadavg').read_text())
  results.append({'target':name,'case':case,'exit':result.returncode,'log':str(log),'load_start':load})
  print(name,case,result.returncode,flush=True)
(scratch/'kernel-results.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(any(row['exit'] for row in results))
