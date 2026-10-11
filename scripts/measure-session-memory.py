#!/usr/bin/env python3
"""Measure only fixture-owned real shims and shells at 200 sessions; retire all children."""
import argparse,json,os,socket,struct,subprocess,sys,time,uuid,signal,shutil,statistics,hashlib
from pathlib import Path
sys.dont_write_bytecode = True
from agent_fixture import Binary, exact, fixture_state, varint
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--sessions', type=int, default=200)
parser.add_argument('--samples', type=int, default=31)
parser.add_argument('--owners', action='store_true', help='also sample 200 independent ownership links across filled history')
parser.add_argument('--facts-only', action='store_true', help='measure registry control latency without filling history')
args = parser.parse_args()
binary = str(args.binary.resolve())
count = args.sessions
assert count > 0 and args.samples > 0
env=dict(os.environ,ZDOTDIR=str(Path.cwd()/"crates/infraternal/tests/profile"))
root=fixture_state('m')
root.mkdir(mode=0o700)
client=None
children=[]
shells=[]
owners=[]
def birth(pid):
 # Cleanup may run after an early child failure; never signal a reused PID.
 try: return Path(f'/proc/{pid}/stat').read_bytes().rsplit(b') ',1)[1].split()[19]
 except (FileNotFoundError,IndexError): return None
def retire(pid, born):
 if born is not None and birth(pid)==born:
  try: os.kill(pid,signal.SIGKILL)
  except ProcessLookupError: pass
def frame(s): return exact(s,struct.unpack('<I',exact(s,4))[0])
def send(s,b): s.sendall(struct.pack('<I',len(b))+b)
def connect(id):
 s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(str(root/'sessions'/f'{id}.sock')); hello=frame(s); assert hello[0]==1; return s

def counters(pid):
 lines=Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines()
 return {k: next(int(l.split()[1]) for l in lines if l.startswith(k+':')) for k in ['Pss','Private_Dirty','Private_Clean']}
def report(label):
 for role,pids in [('shim',[p.pid for _,p in children]),('shell',[pid for pid,_ in shells])]:
  values=[counters(pid) for pid in pids]
  print(json.dumps(dict(phase=label,role=role,count=len(values),total_kib={k:sum(v[k] for v in values) for k in values[0]},mean_kib={k:round(sum(v[k] for v in values)/len(values),2) for k in values[0]},load=Path('/proc/loadavg').read_text().strip())),flush=True)
try:
 print(json.dumps(dict(machine=os.uname().nodename,binary=binary,binary_sha256=hashlib.file_digest(open(binary,'rb'),'sha256').hexdigest(),binary_bytes=Path(binary).stat().st_size,dimensions='80x24',load=Path('/proc/loadavg').read_text().strip())),flush=True)
 for i in range(count):
  id=uuid.uuid4().hex
  p=subprocess.Popen([binary,'__shim','--session',id,'--uid',str(os.getuid()),'--cols','80','--rows','24','--state',str(root)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
  children.append((id,p))
  deadline=time.monotonic()+30
  while True:
   try:
    with connect(id) as s: pass
    break
   except (FileNotFoundError,ConnectionRefusedError):
    assert time.monotonic()<deadline, (i,p.poll()); time.sleep(.01)
  while True:
   ids=Path(f'/proc/{p.pid}/task/{p.pid}/children').read_text().split()
   if ids: shells.append((int(ids[0]),birth(int(ids[0])))); break
   assert time.monotonic()<deadline, (i,p.poll()); time.sleep(.01)
 # Recover 200 real shims, then prove the host can admit session 201.
 client=Binary(Path(binary), root)
 def facts():
  action=b'host.facts.read'
  client.send(0,0x30,struct.pack('<I',151)+varint(len(action))+action+b'{}')
  stream,kind,body=client.read()
  assert (stream,kind)==(0,0x31) and body[4]==1
  return json.loads(body[5:])
 assert (facts()['sessionCount'],facts()['backgroundSessionCount'])==(count,count)
 extra=client.open()
 assert facts()['sessionCount']==count+1
 with connect(extra.hex) as peer:
  pass
 # Only the admitted extra shim is retired; the original 200 stay simultaneous.
 path=root/'sessions'/f'{extra.hex}.sock'
 with socket.socket(socket.AF_UNIX) as peer:
  peer.connect(str(path)); hello=frame(peer)
 pid=struct.unpack('<I',hello[27:31])[0]
 extra_children=Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
 assert len(extra_children)==1
 extra_pid=int(extra_children[0])
 retire(extra_pid,birth(extra_pid))
 deadline=time.monotonic()+1
 while path.exists():
  assert time.monotonic()<deadline
  time.sleep(.005)
 assert facts()['sessionCount']==count
 print(json.dumps(dict(phase='registry',recovered=count,admitted=count+1,after_reap=count)),flush=True)
 timings=[]
 for _ in range(args.samples):
  start=time.monotonic(); assert facts()['sessionCount']==count
  timings.append((time.monotonic()-start)*1000)
 timings.sort()
 print(json.dumps(dict(phase='facts-latency',sessions=count,samples=len(timings),p50_ms=round(statistics.median(timings),3),maximum_ms=round(timings[-1],3),load=Path('/proc/loadavg').read_text().strip())),flush=True)
 if args.facts_only: raise SystemExit(0)
 time.sleep(1)
 report(f'empty-{count}')
 if args.owners:
  # Each negotiated owner is independent of probes and output cursors. Confirm
  # installation before sampling; no PTY output is read through this link.
  for id,p in children:
   peer=connect(id); owners.append(peer)
   send(peer,b'\x02'+struct.pack('<Q',8))
   send(peer,b'\x19')
   assert frame(peer)==b'\x1a'+bytes(16)
  report(f'owned-empty-{count}')
 pid=children[0][1].pid
 print(json.dumps(dict(phase='shim-attribution',threads=len(list(Path(f'/proc/{pid}/task').iterdir())))),flush=True)
 smaps=Path(f'/proc/{pid}/smaps').read_text()
 blocks=[]
 current=None
 for l in smaps.splitlines():
  if '-' in l.split()[0]:
   if current: blocks.append(current)
   current={'mapping':l,'pss_kib':0,'private_dirty_kib':0}
  elif l.startswith('Pss:'): current['pss_kib']=int(l.split()[1])
  elif l.startswith('Private_Dirty:'): current['private_dirty_kib']=int(l.split()[1])
 if current: blocks.append(current)
 for b in blocks:
  if b['private_dirty_kib'] or '[stack]' in b['mapping']: print(json.dumps(dict(phase='shim-attribution',**b)),flush=True)
 # Grow real shell output while detached; probes remain control-only.
 for id,p in children:
  with connect(id) as s:
   send(s,b'\x02'+struct.pack('<Q',0)); send(s,b'\x10'+b"printf 'line %080d\\n' {1..12000}; printf 'DONE_%s\\n' MEASURE\n")
 for id,p in children:
  with connect(id) as s:
   send(s,b'\x02'+struct.pack('<Q',0)); send(s,b'\x13'+struct.pack('<Q',0))
   tail=b''
   while b'DONE_MEASURE\r\n' not in tail:
    data=frame(s)
    assert data[0]==0x11, data[0]
    tail=(tail+data[9:])[-256:]
 report(f'scrollback-{count}')
 if owners:
  for peer in owners: peer.close()
  owners.clear()
  report(f'released-scrollback-{count}')
finally:
 for peer in owners: peer.close()
 if client is not None: client.kill()
 for pid,born in shells: retire(pid,born)
 for id,p in children:
  try: p.wait(timeout=2)
  except subprocess.TimeoutExpired: p.kill(); p.wait()
 shutil.rmtree(root)
