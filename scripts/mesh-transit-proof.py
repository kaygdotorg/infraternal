#!/usr/bin/env python3
"""Reject unrequested subnet transit through a Mesh node in isolated user/network namespaces [163,216], #129."""
import importlib.util,json,socket,struct,subprocess,time,sys
from pathlib import Path
if Path("/proc/self/uid_map").read_text().split()[2:] != ["1"]:
 raise SystemExit("Run inside a disposable user/network namespace: unshare -Urn")
spec=importlib.util.spec_from_file_location("proof",str(Path(__file__).with_name("mesh-namespace-proof.py")))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
third=subprocess.Popen(["unshare","-n","sleep","60"])
child=subprocess.Popen(["unshare","-n","sleep","60"]);nodes=[];listener=None
try:
 time.sleep(.1)
 p.run("ip","link","set","lo","up");p.namespace(child.pid,"ip","link","set","lo","up")
 p.run("ip","link","add","underlay0","type","veth","peer","name","underlay1")
 p.run("ip","link","set","underlay1","netns",str(child.pid))
 p.run("ip","addr","add","10.220.0.1/24","dev","underlay0");p.run("ip","link","set","underlay0","up")
 p.namespace(child.pid,"ip","addr","add","10.220.0.2/24","dev","underlay1");p.namespace(child.pid,"ip","link","set","underlay1","up")
 p.namespace(child.pid,"ip","link","add","transit0","type","veth","peer","name","transit1")
 p.namespace(child.pid,"ip","link","set","transit1","netns",str(third.pid))
 p.namespace(child.pid,"ip","addr","add","10.230.0.1/24","dev","transit0");p.namespace(child.pid,"ip","link","set","transit0","up")
 p.namespace(child.pid,"/usr/sbin/sysctl","-qw","net.ipv4.ip_forward=1")
 p.namespace(third.pid,"ip","addr","add","10.230.0.2/24","dev","transit1");p.namespace(third.pid,"ip","link","set","transit1","up")
 p.namespace(third.pid,"ip","route","add","10.254.0.0/24","via","10.230.0.1")
 fixture=sys.argv[1];extra=sys.argv[2:]
 nodes=[subprocess.Popen([fixture,*extra],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True),subprocess.Popen(["nsenter","-t",str(child.pid),"-n",fixture,*extra],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)]
 identities=[json.loads(n.stdout.readline()) for n in nodes]
 addresses=[{"ipv4":"10.254.0.1","ipv6":"fd01:203:405::1"},{"ipv4":"10.254.0.2","ipv6":"fd01:203:405::2"}]
 for i,n in enumerate(nodes):
  o=1-i
  p.request(n,{"node":i+1,"from_version":None,"version":1,"index":0,"last":True,"addresses":addresses[i],"default_policy":"Allow","upserted":{str(o+1):{"peer":{"key":identities[o]["public_key"],"addresses":({"ipv4":"10.230.0.2","ipv6":"fd01:203:405::3"} if i==0 else addresses[o]),"endpoint":f"10.220.0.{o+1}:{identities[o]['port']}"},"inbound":"All","outbound":"All"}},"removed":[]})
 code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.230.0.2',5222));s.settimeout(3);print('ready',flush=True);\ntry: print('RECEIVED' if s.recv(1024)==b'plaintext' else 'unexpected',flush=True)\nexcept TimeoutError: print('BLOCKED',flush=True)"
 listener=subprocess.Popen(["nsenter","-t",str(third.pid),"-n","python3","-c",code],stdout=subprocess.PIPE,text=True)
 assert listener.stdout.readline().strip()=="ready"
 udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('10.254.0.1',5221));
 for _ in range(3): udp.sendto(b'plaintext',('10.230.0.2',5222));time.sleep(.2)
 udp.close()
 counters=p.request(nodes[1],'stats')
 assert any(peer['received_bytes']>0 for peer in counters), 'tunnel traffic was not observed'
 result=listener.stdout.readline().strip();listener.wait(timeout=3)
 print(json.dumps({'unrequested_subnet_transit':result,'backend':'nf_tables' if extra else 'nft','load':open('/proc/loadavg').read().strip()}),flush=True)
 assert result=='BLOCKED', 'unrequested subnet transit was not refused'
finally:
 for proc in [listener,*nodes,child,third]:
  if proc and proc.poll() is None: proc.terminate();proc.wait(timeout=3)
