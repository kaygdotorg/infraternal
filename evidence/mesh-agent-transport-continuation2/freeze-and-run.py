"""Freeze exact current-source static test artifacts and run the D215 proof on the perf VM."""
import hashlib,json,os,shutil,subprocess,time
from pathlib import Path
ROOT=Path.cwd()
E=ROOT/'evidence/mesh-agent-transport-continuation2'
STAGE=Path.home()/'.cache/codex-scratch/mesh-agent-transport-continuation2/artifacts'
STAGE.mkdir(parents=True,exist_ok=True)
for role in ['server']:
    status=E/(role+'-build.exit')
    while not status.exists(): time.sleep(5)
    if status.read_text().strip()!='0': raise SystemExit(role+' build failed; inspect evidence')
seal=json.loads((E/'frozen-source.json').read_text())
assert all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in seal['files'].items()),'Frozen source changed'
items={}
for role in ['server']:
    messages=[json.loads(l) for l in (E/(role+'-build.jsonl')).read_text().splitlines() if l.startswith('{')]
    units=[v for v in messages if v.get('executable') and v['profile']['test'] and v['target']['name']=='infraternal_'+role]
    assert len(units)==1,'Ambiguous test artifact'
    unit=units[0]
    assert unit['manifest_path']==str(ROOT/'crates'/('infraternal-'+role)/'Cargo.toml')
    assert not unit['fresh'],'Current worktree test executable unexpectedly reused'
    src=Path(unit['executable']);dest=STAGE/(role+'-tests');shutil.copy2(src,dest)
    items[role]={'path':str(src),'bytes':dest.stat().st_size,'sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'cargo_artifact':unit}
shipping=json.loads((E/'shipping-artifact.json').read_text())
shutil.copy2(shipping['path'],STAGE/'shipping-cli')
assert hashlib.sha256((STAGE/'shipping-cli').read_bytes()).hexdigest()==shipping['sha256']
shutil.copy2(E/'run-perf.sh',STAGE/'run-perf.sh')
items['shipping']=shipping
(E/'frozen-artifacts.json').write_text(json.dumps({'source_head':seal['head'],'artifacts':items},indent=2)+'\n')
with (E/'server-catalog.txt').open('w') as f: subprocess.run([str(STAGE/'server-tests'),'--list'],stdout=f,check=True)
for role in ['server']:
    with (E/(role+'-static.txt')).open('w') as f: subprocess.run(['file',str(STAGE/(role+'-tests'))],stdout=f,check=True)
print('Static current-source artifacts frozen; provenance:',E/'frozen-artifacts.json',flush=True)
with (E/'ship.log').open('w') as log:
    pack=subprocess.Popen(['tar','-czf','-','-C',str(STAGE),'shipping-cli','server-tests','run-perf.sh'],stdout=subprocess.PIPE,stderr=log)
    run=subprocess.run(['netbird','ssh','--no-browser','root@10.69.69.208','flock -w 30 /var/lock/perf-bench.lock sh -c "mkdir -p /root/infraternal-bench/mat129-c2; cd /root/infraternal-bench/mat129-c2; tar -xzf -"'],stdin=pack.stdout,stdout=log,stderr=log)
    pack.stdout.close();pack.wait()
    assert run.returncode==0 and pack.returncode==0,'Artifact transfer refused; inspect ship.log'
print('Perf artifacts shipped; running serial locked proof',flush=True)
with (E/'perf-dispatch.log').open('w') as log:
    r=subprocess.run(['netbird','ssh','--no-browser','root@10.69.69.208','flock -w 30 /var/lock/perf-bench.lock sh /root/infraternal-bench/mat129-c2/run-perf.sh namespace-only'],stdout=log,stderr=log)
(E/'perf-dispatch.exit').write_text(str(r.returncode)+'\n')
print('Perf dispatch exit',r.returncode,'evidence:',E/'perf-dispatch.log',flush=True)
