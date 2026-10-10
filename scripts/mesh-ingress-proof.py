#!/usr/bin/env python3
"""Reject underlay ingress to Mesh-bound IPv4 and IPv6 services in isolated user/network namespaces [163,216], #129."""
import importlib.util,json,socket,struct,subprocess,time,sys
from pathlib import Path
if Path("/proc/self/uid_map").read_text().split()[2:] != ["1"]:
 raise SystemExit("Run inside a disposable user/network namespace: unshare -Urn")
spec=importlib.util.spec_from_file_location("proof",str(Path(__file__).with_name("mesh-namespace-proof.py")))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
child=subprocess.Popen(["unshare","-n","sleep","60"]);nodes=[];listener=None
try:
 time.sleep(.1)
 p.run("ip","link","set","lo","up");p.namespace(child.pid,"ip","link","set","lo","up")
 p.run("ip","link","add","underlay0","type","veth","peer","name","underlay1")
 p.run("ip","link","set","underlay1","netns",str(child.pid))
 p.run("ip","addr","add","10.220.0.1/24","dev","underlay0");p.run("ip","link","set","underlay0","up")
 p.namespace(child.pid,"ip","addr","add","10.220.0.2/24","dev","underlay1");p.namespace(child.pid,"ip","link","set","underlay1","up")
 fixture=sys.argv[1];ipv6="--ipv6" in sys.argv[2:];extra=[a for a in sys.argv[2:] if a!="--ipv6"]
 nodes=[subprocess.Popen([fixture,*extra],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True),subprocess.Popen(["nsenter","-t",str(child.pid),"-n",fixture,*extra],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)]
 identities=[json.loads(n.stdout.readline()) for n in nodes]
 addresses=[{"ipv4":"10.254.0.1","ipv6":"fd01:203:405::1"},{"ipv4":"10.254.0.2","ipv6":"fd01:203:405::2"}]
 for i,n in enumerate(nodes):
  o=1-i
  p.request(n,{"node":i+1,"from_version":None,"version":1,"index":0,"last":True,"addresses":addresses[i],"default_policy":"Deny","upserted":{str(o+1):{"peer":{"key":identities[o]["public_key"],"addresses":addresses[o],"endpoint":f"10.220.0.{o+1}:{identities[o]['port']}"},"inbound":"None","outbound":"None"}},"removed":[]})
 code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.254.0.2',5222));s.settimeout(1);print('ready',flush=True);\ntry: print('RECEIVED' if s.recv(1024)==b'plaintext' else 'unexpected',flush=True)\nexcept TimeoutError: print('BLOCKED',flush=True)"
 if ipv6: code=code.replace('socket.AF_INET,','socket.AF_INET6,').replace("'10.254.0.2'","'fd01:203:405::2'")
 listener=subprocess.Popen(["nsenter","-t",str(child.pid),"-n","python3","-c",code],stdout=subprocess.PIPE,text=True)
 assert listener.stdout.readline().strip()=="ready"
 dst=json.loads(p.namespace(child.pid,"ip","-j","link","show","underlay1"))[0]["address"]
 src=json.loads(p.run("ip","-j","link","show","underlay0"))[0]["address"]
 mac=lambda v:bytes.fromhex(v.replace(':',''))
 payload=b'plaintext';udp=struct.pack('!HHHH',5221,5222,8+len(payload),0)+payload
 header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),1,0,64,17,0,socket.inet_aton('10.220.0.1'),socket.inet_aton('10.254.0.2'))
 words=struct.unpack('!10H',header);checksum=sum(words)
 while checksum>>16: checksum=(checksum&65535)+(checksum>>16)
 header=header[:10]+struct.pack('!H',(~checksum)&65535)+header[12:]
 if ipv6:
  src6=socket.inet_pton(socket.AF_INET6,'fdde::1');dst6=socket.inet_pton(socket.AF_INET6,'fd01:203:405::2')
  pseudo=src6+dst6+struct.pack('!I3xB',len(udp),17)
  data=pseudo+udp
  if len(data)%2: data+=b'\x00'
  checksum=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
  while checksum>>16: checksum=(checksum&65535)+(checksum>>16)
  udp=udp[:6]+struct.pack('!H',((~checksum)&65535) or 65535)+udp[8:]
  header=struct.pack('!IHBB16s16s',6<<28,len(udp),17,64,src6,dst6)
 raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);raw.bind(('underlay0',0));raw.send(mac(dst)+mac(src)+(b'\x86\xdd' if ipv6 else b'\x08\x00')+header+udp);raw.close()
 result=listener.stdout.readline().strip();listener.wait(timeout=3)
 print(json.dumps({'denied_mesh_address_plaintext':result,'ipv6':ipv6,'backend':'nf_tables' if extra else 'nft','load':open('/proc/loadavg').read().strip()}),flush=True)
 assert result=='BLOCKED', 'underlay ingress was not refused'
finally:
 for proc in [listener,*nodes,child]:
  if proc and proc.poll() is None: proc.terminate();proc.wait(timeout=3)
