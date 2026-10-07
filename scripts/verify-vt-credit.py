"""Independent partial-credit repaint progress regression for #26 [13][41]."""
import os, sys, time, struct, select
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path('scripts').resolve()))
from agent_fixture import Binary, cleanup, fixture_state
binary=Path(sys.argv[1]).resolve()
grant=int(sys.argv[2]) if len(sys.argv)>2 else 1
faithful=len(sys.argv)>3 and sys.argv[3]=="faithful"
state=fixture_state('vc');state.mkdir(mode=0o700,exist_ok=True)
c=Binary(binary,state)
try:
 c.open();c.attach();c.until(b'shim-test');c.wait_ack()
 c.input(b'stty -echo -opost\n');c.wait_ack()
 # The deployed fixture batches small refunds. Flush startup's retained refund
 # once so the measured producer begins with exactly the full initial window.
 if c.credit_pending:
  c.send(1,0x14,struct.pack('<I',c.credit_pending));c.credit_pending=0
 hold=state/'hold';os.mkfifo(hold)
 ready=state/'ready';done=state/'done';emitter=state/'emit.py'
 payload=(b'A'*78+b'\r\n')*(12*1024*1024//80+1) if faithful else b'A'*(12*1024*1024)
 fixture=state/'output.vt';fixture.write_bytes(bytes([27])+b'c'+payload)
 emitter.write_text('"""Controlled output progress fixture."""\nimport sys\nfrom pathlib import Path\n'+f'sys.stdout.buffer.write(Path({str(fixture.resolve())!r}).read_bytes());sys.stdout.buffer.flush();Path({str(ready.resolve())!r}).touch()\nopen({str(hold.resolve())!r}).read()\nsys.stdout.buffer.write(b"B"*(2*1024*1024));sys.stdout.buffer.flush();Path({str(done.resolve())!r}).touch()\n')
 c.input(f'python3 {emitter.resolve()}\n'.encode())
 # Remaining credit includes startup bytes credited by the fixture.
 start_out=c.out
 while c.out<start_out+1024*1024:c.process(credit=False)
 deadline=time.monotonic()+5
 while not ready.exists() and time.monotonic()<deadline:time.sleep(.01)
 assert ready.exists(),'detached initial producer must finish'
 c.send(1,0x14,struct.pack('<I',grant))
 time.sleep(.15)
 # Resume producer while a repaint is unaffordable, then observe only a file marker.
 with hold.open('w') as f:f.write('resume\n')
 cursor=c.out
 start=time.monotonic()
 while not done.exists() and time.monotonic()-start<1.5:
  if select.select([c.sock],[],[],.02)[0]:c.process(credit=False)
 elapsed=time.monotonic()-start
 print(f'partial-credit progress: grant={grant} bytes faithful={faithful} producer=2097152 bytes completed={done.exists()} elapsed_ms={elapsed*1000:.1f} notices={len(c.events)} repaints={len(c.snapshots)}',flush=True)
 assert not c.events and not c.snapshots, 'no approximation is announced before forwarding'
 assert done.exists(),'unaffordable repaint must detach after 250ms so producer can progress'
 assert c.out==cursor, 'unforwarded repaint must preserve the client cursor'
 # Sufficient new credit resumes exactly one current repaint after the pause.
 c.send(1,0x14,struct.pack('<I',1024*1024))
 deadline=time.monotonic()+5
 while not c.snapshots and time.monotonic()<deadline:
  if select.select([c.sock],[],[],.05)[0]:c.process(credit=False)
 assert len(c.snapshots)==1, 'sufficient credit must recover the current head'
 notices=[e for e in c.events if e.get('type')=='terminal.snapshot']
 assert len(notices)<=1, 'one forwarded repaint has at most one approximation notice'
 print('partial-credit recovery PASS',flush=True)
finally:
 if c.child.poll() is None:c.kill()
 cleanup(state)
