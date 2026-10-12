#!/usr/bin/env python3
"""Require recovery to retain committed refusal while connection cleanup resumes [242], #173."""
import contextlib,copy,importlib.util,json,socket,sys,threading
from pathlib import Path
repo=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('stateproof',repo/'scripts/mesh-access-state-proof.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
s.SERVER=s.SERVER.replace('b,a=s.recvfrom(4096);s.sendto(b,a)','b,a=s.recvfrom(4096)\n  try: s.sendto(b,a)\n  except OSError: pass')
import argparse,os
parser=argparse.ArgumentParser();parser.add_argument('--fixture',required=True);parser.add_argument('--evidence',required=True,type=Path);parser.add_argument('--nf-tables',action='store_true');args=parser.parse_args()
base=args.evidence;base.mkdir(parents=True,exist_ok=True)
os.environ['INFRATERNAL_TEST_STATE_ROOT']=str(base.resolve())
f=s.HeldCampaign.__new__(s.HeldCampaign);flow=None
fallback=args.nf_tables
results=[]
def command(name):
 f.right.stdin.write(name+'\n');f.right.stdin.flush();return json.loads(f.right.stdout.readline())
try:
 with (base/f'restart-{fallback}.log').open('w') as log,contextlib.redirect_stdout(log):f.__init__(args.fixture,fallback)
 flow=s.Flow(f,f.addresses[1]['ipv4'],5540,'udp')
 for attempt in range(10):
  if attempt:
   f.version+=2
   chunk=copy.deepcopy(f.chunks[1]);chunk.update(from_version=None,version=f.version)
   assert s.proof.request(f.right,chunk)['applied']
   flow.socket.setblocking(False)
   try:
    while flow.socket.recv(128):pass
   except BlockingIOError:pass
   flow.socket.settimeout(.7);assert flow.echo()
  assert command('commit-narrow')['committed_without_cleanup']
  flow.socket.settimeout(.005)
  baseline=[flow.echo() for _ in range(10)];assert not any(baseline)
  done=threading.Event();ready=threading.Event();counts={'sent':0,'replies':0}
  def probes():
   while not done.is_set():
    payload=('restart-check:'+str(counts['sent'])).encode();counts['sent']+=1
    flow.socket.send(payload)
    try:
     if flow.socket.recv(128)==payload:counts['replies']+=1
    except socket.timeout:pass
    ready.set()
  thread=threading.Thread(target=probes);thread.start();ready.wait()
  assert command('restore')['restored'];done.set();thread.join()
  results.append(dict(attempt=attempt,baseline_replies=sum(baseline),**counts))
  (base/f'restart-{fallback}.json').write_text(json.dumps(results,indent=2))
  flow.socket.settimeout(.7)
 (base/f'restart-{fallback}.json').write_text(json.dumps(results,indent=2))
 passed=sum(not r['replies'] for r in results)
 print(f'PASS={passed} FAIL={len(results)-passed}')
 if passed!=len(results):raise SystemExit(1)
finally:
 if flow:flow.socket.close()
 for proc in getattr(f,'processes',[]):
  if proc.poll() is None:proc.terminate();proc.wait(timeout=5)
