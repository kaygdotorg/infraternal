#!/usr/bin/env python3
"""Measure production revocation to the last of two live peers refusing packets [134,166], #173.

Reuse the packet campaign's real kernel pair and add a second receiver. Traffic
and control use public fixtures only. Logs remain in files; stdout is a summary.
Control replies emulate the selected RTT independently per authenticated channel.
"""
import argparse
from agent_fixture import rss
import asyncio
import importlib.util
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import time

spec = importlib.util.spec_from_file_location('policy_proof', Path(__file__).with_name('mesh-policy-proof.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
proof = policy.proof

RECEIVER = """import errno,json,socket,sys,time
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_STREAM if len(sys.argv)>2 else socket.SOCK_DGRAM);s.bind((sys.argv[1],5540));s.settimeout(.05)
if len(sys.argv)>2: s.listen()
print('ready',flush=True);arrivals=[];deadline=time.monotonic()+10;connection=None;pending=b''
while time.monotonic()<deadline:
 try:
  if len(sys.argv)>2:
   if connection is None:
    connection,_=s.accept();connection.settimeout(.05)
   data=connection.recv(4096)
   if not data: break
   pending+=data
   while b'\\n' in pending:
    payload,pending=pending.split(b'\\n',1);arrivals.append({'sent_ns':int(payload),'received_ns':time.monotonic_ns()})
  else:
   payload,address=s.recvfrom(4096);arrivals.append({'sent_ns':int(payload),'received_ns':time.monotonic_ns()})
   # A restrictive update may refuse the echo after receive; retain the arrival.
   try: s.sendto(payload,address)
   except OSError as error:
    if error.errno not in (errno.EPERM,errno.ENOKEY): raise
 except TimeoutError: pass
print(json.dumps(arrivals),flush=True)
"""

async def campaign(args):
    fixture = policy.Campaign.__new__(policy.Campaign)
    tasks = set()
    apply_tasks = []
    summary = None
    try:
        await asyncio.wait_for(asyncio.to_thread(fixture.__init__, args.fixture, args.nf_tables), 30)
        third = subprocess.Popen(['unshare','-n','sleep','1800'])
        fixture.processes.append(third)
        for _ in range(200):
            if Path(f'/proc/{third.pid}/ns/net').readlink() != Path('/proc/self/ns/net').readlink(): break
            await asyncio.sleep(.01)
        else: raise RuntimeError('third namespace did not start')
        def remote(*command): return proof.namespace(third.pid, *command)
        proof.run('ip','link','add','underlay2','type','veth','peer','name','underlay3')
        proof.run('ip','link','set','underlay3','netns',str(third.pid))
        proof.run('ip','addr','add','10.221.0.1/24','dev','underlay2')
        proof.run('ip','link','set','underlay2','up')
        remote('ip','link','set','lo','up')
        remote('ip','addr','add','10.221.0.3/24','dev','underlay3')
        remote('ip','link','set','underlay3','up')
        remote('ip','route','add','10.220.0.0/24','via','10.221.0.1')
        extra = ['--nf-tables'] if args.nf_tables else []
        peer2 = fixture.spawn(args.fixture,*extra,namespace_pid=third.pid)
        # Identity is public; the pair's initial templates retain the opposite key/endpoint.
        # Preserve advertised capabilities rather than reconstructing only key/port.
        identities = [*fixture.identities,
            json.loads(await asyncio.wait_for(asyncio.to_thread(peer2.stdout.readline), 10))]
        nodes = [fixture.left,fixture.right,peer2]
        error_log = (args.evidence/'coordinator.log').open('w')
        coordinator = await asyncio.create_subprocess_exec(args.coordinator,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=error_log)
        async def send(value):
            coordinator.stdin.write((json.dumps(value)+'\n').encode());await coordinator.stdin.drain()
        await send({'type':'Init','identities':identities,'extra_members':args.extra_members,'change':args.change})
        initialized = set()
        installed = {}
        applied = {}
        completed = {}
        refusal_clocks = {}
        measuring = False
        initial_versions = {}
        locks = [asyncio.Lock() for _ in nodes]
        async def request(index, value):
            def observe():
                reply = proof.request(nodes[index], value)
                if isinstance(reply, dict):
                    reply['_observed_ns'] = time.monotonic_ns()
                return reply
            async with locks[index]:
                return await asyncio.wait_for(asyncio.to_thread(observe), 10)
        revoked = asyncio.Event()
        frames_log = (args.evidence/'control-frames.jsonl').open('w')
        async def apply(frame):
            dispatched_ns = time.monotonic_ns()
            index=frame['node'];chunk=frame['chunk']
            await asyncio.sleep(args.rtt_ms/2000)
            reply=await request(index, chunk)
            frames_log.write(json.dumps({'node':index,'version':chunk['version'],'index':chunk['index'],'last':chunk['last'],'dispatched_ns':dispatched_ns,'apply_us':reply['apply_us'],'at_ns':reply['_observed_ns'],'refusing_ns':reply.get('refusing_ns')})+'\n');frames_log.flush()
            if chunk['last']:
                if index not in initialized:
                    initialized.add(index);installed[index]=chunk['addresses'];initial_versions[index]=chunk['version']
                elif measuring and index in (1,2) and chunk['version']>initial_versions[index]:
                    # Ignore startup replays and unrelated completed frames. The
                    # final acknowledgment must correspond to actual key removal.
                    if args.change in ('RuleRemoval','DefaultTightening') or len(await request(index, 'stats')) == 2 + args.extra_members:
                        assert reply['applied'], 'final access update was refused'
                        completed.setdefault(index, reply['_observed_ns'])
                        refusal_clocks[index] = 'kernel-install' if reply.get('refusing_ns') else 'completion'
                        applied.setdefault(index, reply.get('refusing_ns') or reply['_observed_ns'])
            if index == 0 and chunk['last']:
                # Independent receiving enforcement needs the sender's filter
                # removed. Its subprocesses cannot stall other completion records.
                await asyncio.to_thread(fixture.remove_sender_filter, True)
            await asyncio.sleep(args.rtt_ms/2000)
            await send({'type':'Ack','call':frame['call'],'reply':{'applied':reply['applied'],'version':chunk['version']}})
        async def dispatch():
            while line:=await coordinator.stdout.readline():
                frame=json.loads(line)
                if frame['type']=='apply':
                    task=asyncio.create_task(apply(frame));tasks.add(task);apply_tasks.append(task)
                elif frame['type']=='revoked':
                    assert frame['success'];revoked.set()
        dispatcher=asyncio.create_task(dispatch());tasks.add(dispatcher)
        deadline=time.monotonic()+60
        while len(initialized)<3:
            for task in apply_tasks:
                if task.done(): task.result()
            assert time.monotonic()<deadline,'initial configuration timeout'
            if dispatcher.done(): dispatcher.result();raise RuntimeError('coordinator closed before initialization')
            await asyncio.sleep(.01)
        await asyncio.wait_for(asyncio.gather(*apply_tasks),30)
        # Snapshot count is queried from actual kernel counters before timing.
        counts=[len(await request(index, 'stats')) for index in range(len(nodes))]
        assert counts==[3+args.extra_members]*3,counts
        fixture.remove_sender_filter()
        if args.rtt_ms:
            for interface in ('underlay0','underlay2'):
                proof.run('tc','qdisc','add','dev',interface,'root','netem','delay',f'{args.rtt_ms/2}ms')
            fixture.remote('tc','qdisc','add','dev','underlay1','root','netem','delay',f'{args.rtt_ms/2}ms')
            remote('tc','qdisc','add','dev','underlay3','root','netem','delay',f'{args.rtt_ms/2}ms')
        measured_rtt=[]
        for index,address in ((1,'10.220.0.2'),(2,'10.221.0.3')):
            # Neighbor discovery adds its own round trip to the first sample.
            # Retain it separately, then calibrate the established test link.
            warmup = await asyncio.wait_for(asyncio.to_thread(proof.run,'ping','-n','-c','1','-W','3',address), 6)
            (args.evidence/f'peer-{index}-neighbor-warmup.log').write_text(warmup)
            ping=await asyncio.wait_for(asyncio.to_thread(proof.run,'ping','-n','-c','3','-i','.2','-W','3',address), 12)
            (args.evidence/f'peer-{index}-underlay-rtt.log').write_text(ping)
            match=re.search(r'= ([0-9.]+)/([0-9.]+)/([0-9.]+)/',ping)
            assert match, 'underlay RTT measurement missing'
            average=float(match.group(2));measured_rtt.append(average)
            if args.rtt_ms: assert args.rtt_ms*.9<=average<=args.rtt_ms*1.3, 'requested RTT not established'
        receivers=[]
        for index,pid in ((1,fixture.child.pid),(2,third.pid)):
            for family in ('ipv4','ipv6'):
                for protocol in (('udp','tcp') if args.change else ('udp',)):
                    receiver=fixture.spawn('python3','-c',RECEIVER,installed[index][family],*(['tcp'] if protocol=='tcp' else []),namespace_pid=pid)
                    receivers.append((index,family,protocol,receiver))
                    assert (await asyncio.wait_for(asyncio.to_thread(receiver.stdout.readline), 10)).strip()=='ready'
        streams=[]
        if args.change:
            for index in (1,2):
                for family in ('ipv4','ipv6'):
                    stream=await asyncio.to_thread(socket.create_connection,(installed[index][family],5540),5)
                    streams.append((index,family,stream))
        stop=asyncio.Event()
        async def packets():
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as v4, socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as v6:
                v4.bind((installed[0]['ipv4'],0));v6.bind((installed[0]['ipv6'],0))
                while not stop.is_set():
                    for index in (1,2):
                        for family,sender in (('ipv4',v4),('ipv6',v6)):
                            try: sender.sendto(str(time.monotonic_ns()).encode(),(installed[index][family],5540))
                            except PermissionError: pass
                    for index,family,stream in streams:
                        try: stream.sendall((str(time.monotonic_ns())+'\n').encode())
                        except OSError: pass
                    await asyncio.sleep(.005)
        sender=asyncio.create_task(packets());tasks.add(sender)
        await asyncio.sleep(.3+args.rtt_ms/1000)
        applied.clear()
        completed.clear()
        measuring = True
        started=time.monotonic_ns()
        await send({'type':'Change','operation':args.change} if args.change else {'type':'Revoke'})
        deadline=time.monotonic()+30
        while len(applied)<2 or not revoked.is_set():
            for task in apply_tasks:
                if task.done(): task.result()
            assert time.monotonic()<deadline,'revocation publication timeout'
            if dispatcher.done(): dispatcher.result();raise RuntimeError('coordinator closed before withdrawal')
            await asyncio.sleep(.005)
        last_apply=max(applied.values())
        assert min(applied.values()) >= started, 'retirement timing used a startup replay'
        await asyncio.sleep(.4+args.rtt_ms/1000)
        stop.set();await sender
        for index,family,stream in streams: stream.close()
        # Receivers retain arrival timestamps only; packet payloads and keys are never captured.
        observed=[]
        for index,family,protocol,receiver in receivers:
            arrivals=json.loads(await asyncio.wait_for(asyncio.to_thread(receiver.stdout.readline), 12))
            assert receiver.wait(timeout=5)==0
            (args.evidence/f'peer-{index}-{family}-{protocol}-arrivals.json').write_text(json.dumps(arrivals)+'\n')
            assert arrivals and min(row['received_ns'] for row in arrivals)<started,'service never reached before revocation'
            assert max(row['sent_ns'] for row in arrivals)<=applied[index], 'revoked packet arrived after key retirement'
            observed.append({'peer':index,'family':family,'protocol':protocol,'received':len(arrivals),'last_packet_us':(max(row['received_ns'] for row in arrivals)-started)/1000,'retired_us':(applied[index]-started)/1000})
        after=[len(await request(index, 'stats')) for index in (1,2)]
        assert after==[(3 if args.change in ('RuleRemoval','DefaultTightening') else 2)+args.extra_members]*2,after
        memory = [rss(node.pid) * 1024 for node in nodes]
        summary={'node_fixture_rss_bytes':memory,'projected_1000_nodes_rss_bytes':max(memory)*1000,'coordinator_three_live_workers_rss_bytes':rss(coordinator.pid)*1024,'result':'PASS','public_journal':args.stateful,'change':args.change or 'PeerRetirement','backend':'nf_tables' if args.nf_tables else 'nft','machine':socket.gethostname(),'rtt_ms':args.rtt_ms,'load':Path('/proc/loadavg').read_text().strip(),'live_peers':2,'measured_underlay_rtt_ms':measured_rtt,'installed_peers_before':counts,'installed_peers_after':after,'change_started_ns':started,'last_apply_ns':last_apply,'durable_completion_us':(max(completed.values())-started)/1000,'refusal_clock': refusal_clocks,'revocation_to_last_peer_refusing_us':(last_apply-started)/1000,'peers':observed}
        await asyncio.wait_for(asyncio.gather(*apply_tasks), 10)
        coordinator.stdin.close()
        await asyncio.wait_for(coordinator.wait(), 5)
        await asyncio.wait_for(dispatcher, 5)
        assert coordinator.returncode==0
        error_log.close();frames_log.close()
    finally:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        if 'coordinator' in locals() and coordinator.returncode is None:
            coordinator.terminate()
            try: await asyncio.wait_for(coordinator.wait(), 3)
            except TimeoutError:
                coordinator.kill();await asyncio.wait_for(coordinator.wait(), 3)
        failures=[]
        for process in reversed(getattr(fixture,'processes',[])):
            if process.poll() is not None: continue
            try:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=3)
            except (OSError,subprocess.TimeoutExpired) as error: failures.append(str(error))
        if failures: raise RuntimeError('fixture cleanup failed: '+ '; '.join(failures))
    return summary

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',required=True);parser.add_argument('--coordinator',required=True)
    parser.add_argument('--evidence',type=Path,required=True);parser.add_argument('--nf-tables',action='store_true')
    parser.add_argument('--rtt-ms',type=int,choices=(0,150),default=0);parser.add_argument('--extra-members',type=int,default=997)
    parser.add_argument('--stateful',action='store_true',help='Use the public-journal fixture and include persistence in apply')
    parser.add_argument('--budget-ms',type=float,help='Fail after retaining evidence when change-to-last-refusal exceeds this budget')
    parser.add_argument('--change',choices=('PeerRetirement','RuleRemoval','DefaultTightening'))
    args=parser.parse_args();args.evidence.mkdir(parents=True,exist_ok=True)
    if args.stateful:
        state_root=args.evidence/'node-state'
        state_root.mkdir(mode=0o700,exist_ok=True)
        os.environ['INFRATERNAL_TEST_STATE_ROOT']=str(state_root.resolve())
    assert Path('/proc/self/uid_map').read_text().split()[2:]==['1'],'run inside unshare -Urn'
    os.environ['PATH']='/usr/sbin:'+os.environ.get('PATH','')
    summary=asyncio.run(campaign(args))
    (args.evidence/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    if args.budget_ms is not None:
        elapsed_ms=summary['revocation_to_last_peer_refusing_us']/1000
        print(f'BUDGET change_to_last_refusal_ms={elapsed_ms:.3f} maximum_ms={args.budget_ms:.3f}',flush=True)
        if elapsed_ms>args.budget_ms:
            raise SystemExit(1)
    print('PASS=1 FAIL=0',flush=True)
if __name__=='__main__': main()
