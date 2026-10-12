"""Freeze the current-source agent test binary and serialize its perf checks after namespace proofs."""
import hashlib,json,shutil,subprocess,time
from pathlib import Path
E=Path.cwd()/'evidence/mesh-agent-transport-continuation2'
STAGE=Path.home()/'.cache/codex-scratch/mesh-agent-transport-continuation2/artifacts'
messages=[json.loads(l) for l in (E/'agent-build.jsonl').read_text().splitlines() if l.startswith('{')]
units=[v for v in messages if v.get('executable') and v['profile']['test'] and v['target']['name']=='infraternal_agent']
assert len(units)==1 and not units[0]['fresh']
u=units[0];src=Path(u['executable']);dst=STAGE/'agent-tests';shutil.copy2(src,dst)
(E/'frozen-agent-artifact.json').write_text(json.dumps({'path':str(src),'bytes':dst.stat().st_size,'sha256':hashlib.sha256(dst.read_bytes()).hexdigest(),'cargo_artifact':u},indent=2)+'\n')
shutil.copy2(E/'run-agent-perf.sh',STAGE/'run-agent-perf.sh')
with (E/'agent-catalog.txt').open('w') as f:subprocess.run([str(dst),'--list'],stdout=f,check=True)
while not (E/'perf-dispatch.exit').exists():time.sleep(5)
assert (E/'perf-dispatch.exit').read_text().strip()=='0','Namespace dispatch failed; inspect preserved evidence'
with (E/'agent-ship.log').open('w') as log:
 p=subprocess.Popen(['tar','-czf','-','-C',str(STAGE),'agent-tests','run-agent-perf.sh'],stdout=subprocess.PIPE,stderr=log)
 r=subprocess.run(['netbird','ssh','--no-browser','root@10.69.69.208','flock -w 30 /var/lock/perf-bench.lock sh -c "cd /root/infraternal-bench/mat129-c2; tar -xzf -"'],stdin=p.stdout,stdout=log,stderr=log)
 p.stdout.close();p.wait();assert r.returncode==0 and p.returncode==0
with (E/'agent-perf-dispatch.log').open('w') as log:
 r=subprocess.run(['netbird','ssh','--no-browser','root@10.69.69.208','flock -w 30 /var/lock/perf-bench.lock sh /root/infraternal-bench/mat129-c2/run-agent-perf.sh'],stdout=log,stderr=log)
(E/'agent-perf-dispatch.exit').write_text(str(r.returncode)+'\n')
print('Agent perf dispatch exit',r.returncode,'evidence:',E/'agent-perf-dispatch.log')
