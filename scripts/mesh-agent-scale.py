#!/usr/bin/env python3
"""Measure shipping infraternal agent apply and idle cost with 1,000 public peers [169,170]."""
import argparse, hashlib, ipaddress, json, os, subprocess, sys, time
from pathlib import Path
from mesh_agent_fixture import BinaryNode

def usage(pid):
    fields=Path(f"/proc/{pid}/stat").read_text().split()
    ticks=int(fields[13])+int(fields[14])
    rss=int(next(x.split()[1] for x in Path(f"/proc/{pid}/status").read_text().splitlines() if x.startswith("VmRSS:")))*1024
    return ticks,rss

def main():
    assert Path("/proc/self/uid_map").read_text().split()[2:]==["1"], "isolated user namespace required"
    a=argparse.ArgumentParser();a.add_argument("--binary",required=True);a.add_argument("--scratch",required=True);args=a.parse_args()
    subprocess.run(["ip","link","set","lo","up"],check=True)
    node=BinaryNode(args.binary,args.scratch)
    try:
        peers={}
        for i in range(2,1002):
            peers[str(i)]={"peer":{"key":list(hashlib.sha256(f"public-peer-{i}".encode()).digest()),"addresses":{"ipv4":str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("10.254.0.0"))+i)),"ipv6":str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("fd00::"))+i))},"endpoint":None},"inbound":"All","outbound":"All"}
        template={"node":1,"from_version":None,"version":1,"index":0,"last":False,"addresses":{"ipv4":"10.254.0.1","ipv6":"fd00::1"},"default_policy":"Allow","upserted":{},"merged":{},"removed":[]}
        chunks=[];chunk=dict(template);chunk["upserted"]={}
        for key,value in peers.items():
            chunk["upserted"][key]=value
            if len(json.dumps(chunk,separators=(",",":")).encode())>8000:
                del chunk["upserted"][key];chunks.append(chunk)
                chunk=dict(template);chunk["index"]=len(chunks);chunk["upserted"]={key:value}
        chunk["last"]=True;chunks.append(chunk)
        start=time.monotonic_ns()
        for chunk in chunks:
            assert len(json.dumps(chunk,separators=(",",":")).encode())<=8192
            result=node.request(chunk)
        apply=(time.monotonic_ns()-start)//1000
        assert result["applied"] and node.call("mesh.status",{})["peer_count"]==1000
        delta=dict(template);delta.update(from_version=1,version=2,last=True,upserted={"2":peers["2"]})
        peers["2"]["peer"]["endpoint"]="127.0.0.1:51820"
        changed=node.request(delta);assert changed["applied"]
        page=node.call("mesh.peers",{});count=0
        while True:
            count+=len(page["peers"])
            if page["next_cursor"] is None:break
            page=node.call("mesh.peers",{"cursor":page["next_cursor"]})
        assert count==1000
        before,rss_on=usage(node.pid);time.sleep(10);after,rss_on=usage(node.pid)
        proc=subprocess.run([args.binary,"mesh","peers","--json","--state",str(node.state)],capture_output=True,text=True)
        assert proc.returncode==0
        pages=[json.loads(line) for line in proc.stdout.splitlines()]
        assert sum(len(page["peers"]) for page in pages)==1000
        down_start=time.monotonic_ns()
        node.call("mesh.down",{});assert node.call("mesh.status",{})["state"]=="Off"
        down_us=(time.monotonic_ns()-down_start)//1000
        before_off,rss_off=usage(node.pid);time.sleep(10);after_off,rss_off=usage(node.pid)
        # Local CLI reads the same running public registry and renders its declarations.
        for command in (["mesh","status","--json"],["mesh","status"],["mesh","peers","--json"]):
            command=command+["--state",str(node.state)]
            proc=subprocess.run([args.binary,*command],capture_output=True,text=True)
            assert proc.returncode==0, "public CLI refused"
            if "--json" in command:json.loads(proc.stdout)
        proc=subprocess.run([args.binary,"mesh","up","--state",str(node.state)],capture_output=True,text=True)
        assert proc.returncode==0 and "Waiting" in proc.stdout
        assert node.call("mesh.status",{})["state"]=="Waiting"
        for chunk in chunks:
            chunk["version"]=3
            node.request(chunk)
        assert node.call("mesh.status",{})["state"]=="On"
        proc=subprocess.run([args.binary,"mesh","down","--json","--state",str(node.state)],capture_output=True,text=True)
        assert proc.returncode==0 and json.loads(proc.stdout)["state"]=="Off"
        for command in (["mesh","--help"],["skill","mesh","--json"]):
            proc=subprocess.run([args.binary,*command],capture_output=True,text=True)
            assert proc.returncode==0
            assert "mesh.identity" not in proc.stdout and "mesh.configure" not in proc.stdout
            if "--json" in command:
                actions=json.loads(proc.stdout)["data"]["commands"]
                assert {x["command"] for x in actions}>={"mesh status","mesh peers","mesh up","mesh down"}
                assert all(x["description"] for x in actions)
        print(json.dumps({"peer_count":1000,"chunks":len(chunks),"apply_us_including_fsync":apply,"one_endpoint_us_including_fsync":changed["apply_us"],"down_us":down_us,"idle_ticks_10s_on":after-before,"idle_ticks_10s_off":after_off-before_off,"rss_bytes_on":rss_on,"rss_bytes_off":rss_off,"rss_bytes_at_1000_nodes":rss_on*1000,"load":Path("/proc/loadavg").read_text().strip(),"public_cli":"pass"},sort_keys=True))
    finally:node.close()

if __name__=="__main__":main()
