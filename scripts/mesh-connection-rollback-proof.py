#!/usr/bin/env python3
"""Require failed journal updates to preserve open connection state exactly [242], #173."""
import contextlib,copy,importlib.util,json,sys
from pathlib import Path
repo=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('stateproof',repo/'scripts/mesh-access-state-proof.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
import argparse,os
parser=argparse.ArgumentParser();parser.add_argument('--fixture',required=True);parser.add_argument('--evidence',required=True,type=Path);parser.add_argument('--nf-tables',action='store_true');args=parser.parse_args()
base=args.evidence;base.mkdir(parents=True,exist_ok=True)
os.environ['INFRATERNAL_TEST_STATE_ROOT']=str(base.resolve())
f=s.HeldCampaign.__new__(s.HeldCampaign);flows=[]
try:
 with (base/'fixture.log').open('w') as log,contextlib.redirect_stdout(log):f.__init__(args.fixture,args.nf_tables)
 for family in ('ipv4','ipv6'):
  for protocol in ('tcp','udp'):flows.append(s.Flow(f,f.addresses[1][family],5540,protocol))
 def dump():return json.loads(f.remote('python3',str(repo/'scripts/mesh-access-state-proof.py'),'--dump'))
 before=dump()
 f.right.stdin.write('obstruct\n');f.right.stdin.flush();assert json.loads(f.right.stdout.readline())['obstructed']
 chunk=copy.deepcopy(f.chunks[1]);chunk.update(from_version=f.version,version=f.version+1)
 chunk['upserted']['1']['inbound']='None'
 reply=s.proof.request(f.right,chunk);assert reply['failed'],reply
 after=dump()
 results=[]
 for flow in flows:
  echoes=[flow.echo(),flow.echo()]
  current=dump();b=flow.row(before);a=flow.row(after);c=flow.row(current)
  results.append(dict(family=flow.address,protocol=flow.protocol,before_id=b['id'] if b else None,after_delete_id=a['id'] if a else None,after_echo_id=c['id'] if c else None,echoes=echoes))
 (base/'results.json').write_text(json.dumps(dict(reply=reply,results=results),indent=2))
 passed=sum(x['before_id']==x['after_delete_id'] and all(x['echoes']) for x in results)
 print(f'PASS={passed} FAIL={len(results)-passed}')
 if passed!=len(results):raise SystemExit(1)
finally:
 for flow in flows:flow.socket.close()
 for proc in getattr(f,'processes',[]):
  if proc.poll() is None:proc.terminate();proc.wait(timeout=5)
