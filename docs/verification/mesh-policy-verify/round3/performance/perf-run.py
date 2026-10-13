"""Interleave immutable native latency artifacts and measure delayed retirement under the booked lock."""
import json,os,signal,socket,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parent
state=Path('/root/infraternal-bench/mesh-policy/s173');state.mkdir(mode=0o700,exist_ok=True)
os.environ.update(PYTHONDONTWRITEBYTECODE='1',TRACER_TEST_PORT='4473',INFRATERNAL_TEST_STATE_ROOT=str(state))
sys.path.insert(0,str(root/'scripts'))
# The fixture is local to this report; the output-path helper lives in repository scripts.
sys.path.insert(1,str(Path(__file__).resolve().parents[5]/'scripts'))
from agent_fixture import cleanup
from evidence_path import evidence_directory
out=evidence_directory('mesh-policy-verify-round3');out.mkdir(parents=True,exist_ok=True)
rows=[]
def execute(name,command,env=None,timeout=119):
 before=Path('/proc/loadavg').read_text().strip();started=time.monotonic()
 with (out/(name+'.log')).open('w') as log:
  process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=True)
  try:code=process.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   os.killpg(process.pid,signal.SIGTERM)
   try:process.wait(timeout=3)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
   code=124
 row={'name':name,'exit':code,'elapsed_s':time.monotonic()-started,'load_before':before,'load_after':Path('/proc/loadavg').read_text().strip(),'machine':socket.gethostname()}
 rows.append(row);(out/'runs.json').write_text(json.dumps(rows,indent=2)+'\n')
 print('run '+name+' '+('PASS' if code==0 else 'FAIL'),flush=True)
 return code
counter=0
for rtt in (0,150,300):
 for candidate in ('base','head','head','base'):
  env=dict(os.environ,INFRATERNAL_TEST_RTT=str(rtt));folder=state/str(counter)
  execute(f'latency-{rtt}-{counter}-{candidate}',['systemd-run','--user','--scope','-p','CPUWeight=10000','python3',str(root/'scripts/verify-latency.py'),'--binary',str(root/(candidate+'-infraternal')),'--state',str(folder),'--samples','100'],env)
  cleanup(folder);counter+=1
for backend in ('nft','nf_tables'):
 command=['systemd-run','--user','--scope','-p','CPUWeight=10000','unshare','-Urn','python3',str(root/'scripts/mesh-revocation-proof.py'),'--fixture',str(root/'head-kernel-node'),'--coordinator',str(root/'head-coordinator'),'--evidence',str(out/('retirement-150-'+backend)),'--rtt-ms','150']
 if backend=='nf_tables':command.append('--nf-tables')
 execute('retirement-150-'+backend,command,timeout=90)
print('perf counts '+str(sum(r['exit']==0 for r in rows))+' PASS, '+str(sum(r['exit']!=0 for r in rows))+' FAIL',flush=True)
