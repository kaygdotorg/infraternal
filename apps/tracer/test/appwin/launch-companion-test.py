"""Role: check independent app launch arguments and real pipe/EOF forwarding without accessing a desktop (#146)."""
import importlib.util
import os
import pathlib
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = pathlib.Path(os.environ.get('APP_WINDOW_LAUNCHER_SOURCE', pathlib.Path(__file__).with_name('launch-companion.py')))
spec = importlib.util.spec_from_file_location('companion_launch', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SCRATCH = pathlib.Path(os.environ.get(
    'APP_WINDOW_TEST_SCRATCH',
    pathlib.Path.home() / '.cache/codex-scratch/app-windows-latency-r3b/launcher-tests'))
SCRATCH.mkdir(parents=True, exist_ok=True)


class LaunchTests(unittest.TestCase):
    """The app owns its launch; the bridge owns only its private pipes and PIDs."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.native = self.root / 'Helper.app/Contents/MacOS/Helper'
        self.native.parent.mkdir(parents=True)
        self.native.touch()

    def test_only_an_app_bundle_is_accepted(self):
        with self.assertRaises(ValueError):
            module.app_bundle(SOURCE)

    def test_launchservices_owns_the_signed_app_and_its_stdio(self):
        command = module.open_command(self.native, 'in', 'out', 'err', ['--surface-capture'], 'owned-pid')
        self.assertEqual(command[:4], ['/usr/bin/open', '-n', '-W', '-g'])
        self.assertEqual(command[-6:], [str(self.native.parent.parent.parent), '--args', '--responsible-child',
                                        '--launch-pid-file', 'owned-pid', '--surface-capture'])
        self.assertNotIn(str(self.native), command)
        self.assertEqual(command[4:10], ['--stdin', 'in', '--stdout', 'out', '--stderr', 'err'])

    def bridge(self, cancel_at_input_start=False, finish_before_output=False, exit_before_identity=False,
               missing_live_identity=False, unrelated_sibling=False):
        # Substitute only the platform launcher. Everything after it uses real
        # processes, FIFO backpressure, standard pipes and native EOF behavior.
        runner = '''import importlib.util,pathlib,subprocess,sys
sys.path.insert(0,str(pathlib.Path(sys.argv[1]).parent))
spec=importlib.util.spec_from_file_location('launch',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
children=[];siblings=[];real=m.subprocess.Popen
def launch(*a,**kw):
 if sys.argv[4]=='unrelated-sibling':siblings.append(real([sys.executable,'-c','import time; time.sleep(60)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
 p=real(*a,**kw);children.append(p)
 return p
m.subprocess.Popen=launch
m.app_pids=lambda executable:{p.pid for p in children+siblings if p.poll() is None}
m.process_identity=lambda pid:(pid,1792436400,123456)
def command(executable,incoming,outgoing,errors,arguments,launch_record=None):
 if launch_record is None:launch_record=pathlib.Path(sys.argv[3])/'launch-pid'
 record="open(sys.argv[1],'x').write(str(__import__('os').getpid())+chr(10)); "
 if sys.argv[4]=='exit-before-identity':
  return [sys.executable,'-c',"import pathlib,sys,time; "+record+"b=open(sys.argv[2],'wb',buffering=0); release=pathlib.Path(sys.argv[3]); next(i for i in range(5000) if release.exists() or time.sleep(.001)); b.write(bytes.fromhex('7b2273637265656e5f7265636f7264696e67223a747275652c226465766963655f636f6e74726f6c223a747275657d0a')); b.close()",str(launch_record),str(outgoing),sys.argv[3]+'/release']
 if sys.argv[4]=='finish-before-output':
  return [sys.executable,'-c',"import pathlib,sys; "+record+"a=open(sys.argv[2],'rb',buffering=0); b=open(sys.argv[3],'wb',buffering=0); pathlib.Path(sys.argv[4]).write_text('ready'); data=a.read(); b.write(data); a.close(); b.close()",str(launch_record),str(incoming),str(outgoing),sys.argv[3]+'/reader-ready']
 return [sys.executable,'-c',"import sys; "+record+"a=open(sys.argv[2],'rb',buffering=0); b=open(sys.argv[3],'wb',buffering=0); data=a.read(); b.write(data); a.close(); b.close()",str(launch_record),str(incoming),str(outgoing)]
m.open_command=command
if sys.argv[4]=='live-without-identity':m.process_identity=lambda pid:None
if sys.argv[4]=='exit-before-identity':
 def identity(pid):
  pathlib.Path(sys.argv[3]+'/release').touch()
  children[0].wait(timeout=5)
  return None
 m.process_identity=identity
if sys.argv[4]=='cancel-input-start':
 import atexit,os,signal
 def cleanup_children():
  for p in children:
   if p.poll() is None:p.terminate()
   p.wait(timeout=3)
 atexit.register(cleanup_children)
 class Thread(m.threading.Thread):
  def start(self):
   if self._target.__name__=='forward_input':os.kill(os.getpid(),signal.SIGTERM)
   return super().start()
 m.threading.Thread=Thread
if sys.argv[4]=='finish-before-output':
 real_select=m.select.select;real_pipe=m.os.pipe;finished=False;pipes=[]
 def pipe():
  pair=real_pipe();pipes.append(pair);return pair
 m.os.pipe=pipe
 def select(readers,writers,errors,timeout=None):
  global finished
  if writers==[1] and not finished:
   finished=True
   # Order the normal app-finished wake ahead of the pending stdout write.
   m.os.write(next(w for r,w in pipes if r==readers[0]),b'x')
  return real_select(readers,writers,errors,timeout)
 m.select.select=select
result=0
try:result=m.run(sys.argv[2],sys.argv[3],sys.argv[3]+'/errors',sys.argv[3]+'/pids',[])
except InterruptedError:
 if sys.argv[4]!='unrelated-sibling':raise
finally:
 if siblings:
  with open(sys.argv[3]+'/pids','a') as log:log.write('unrelated '+str(siblings[0].pid)+' '+('alive' if siblings[0].poll() is None else str(siblings[0].returncode))+chr(10))
  for sibling in siblings:
   if sibling.poll() is None:sibling.terminate()
   sibling.wait(timeout=3)
raise SystemExit(result)
'''
        mode = ('cancel-input-start' if cancel_at_input_start else
                'finish-before-output' if finish_before_output else
                'exit-before-identity' if exit_before_identity else
                'live-without-identity' if missing_live_identity else
                'unrelated-sibling' if unrelated_sibling else 'normal')
        return subprocess.Popen([sys.executable, '-c', runner, str(SOURCE), str(self.native), str(self.root),
                                 mode],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_stream_bytes_and_eof_reach_the_independent_app(self):
        process = self.bridge()
        data = bytes(range(256)) * 8192
        out, errors = process.communicate(data, timeout=15)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(out, data)
        self.assertEqual(list(self.root.glob('launch-*')), [])
        rows = (self.root / 'pids').read_text().splitlines()
        native = next(row for row in rows if row.startswith('native '))
        self.assertEqual(len(native.split()), 4)
        self.assertEqual(native.split()[2:], ['1792436400', '123456'])
        for row in rows:
            with self.assertRaises(ProcessLookupError):
                os.kill(int(row.split()[1]), 0)

    def test_cancelling_the_bridge_retires_its_app(self):
        process = self.bridge()
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 10
        while not (self.root / 'pids').exists() or 'native ' not in (self.root / 'pids').read_text():
            if time.monotonic() > deadline:
                self.fail('independent app did not start')
            time.sleep(.01)
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=10)
        for row in (self.root / 'pids').read_text().splitlines():
            with self.assertRaises(ProcessLookupError):
                os.kill(int(row.split()[1]), 0)
        self.assertEqual(list(self.root.glob('launch-*')), [])

    def test_cancelling_the_bridge_does_not_retire_an_unrelated_same_executable(self):
        process = self.bridge(unrelated_sibling=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 10
        while not (self.root / 'pids').exists() or 'native ' not in (self.root / 'pids').read_text():
            if time.monotonic() > deadline:
                self.fail('independent app did not start')
            time.sleep(.01)
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=10)
        unrelated = next(row for row in (self.root / 'pids').read_text().splitlines()
                         if row.startswith('unrelated '))
        self.assertEqual(unrelated.split()[2], 'alive', 'bridge cancellation signalled a sibling process')
        self.assertEqual(list(self.root.glob('launch-*')), [])

    def test_cancellation_during_thread_start_cannot_interrupt_cleanup(self):
        process = self.bridge(cancel_at_input_start=True)
        _, errors = process.communicate(timeout=10)
        self.assertNotIn(b'RuntimeError', errors)
        for row in (self.root / 'pids').read_text().splitlines():
            with self.assertRaises(ProcessLookupError):
                os.kill(int(row.split()[1]), 0)
        self.assertEqual(list(self.root.glob('launch-*')), [])

    def test_cancellation_retires_an_app_while_the_consumer_stops_reading(self):
        process = self.bridge()
        try:
            process.stdin.write(bytes(range(256)) * 8192)
            process.stdin.close()
            process.stdin = None
            self.assertTrue(select.select([process.stdout], [], [], 5)[0])
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=5)
        finally:
            # Drain on failure too, so a red backpressure regression cannot
            # strand the fixture's real subprocesses or pipe descriptors.
            process.communicate(timeout=15)
        for row in (self.root / 'pids').read_text().splitlines():
            with self.assertRaises(ProcessLookupError):
                os.kill(int(row.split()[1]), 0)

    def test_a_live_app_without_kernel_identity_remains_refused(self):
        process = self.bridge(missing_live_identity=True)
        out, _ = process.communicate(timeout=15)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(out, b'')
        for row in (self.root / 'pids').read_text().splitlines():
            with self.assertRaises(ProcessLookupError):
                os.kill(int(row.split()[1]), 0)
        self.assertEqual(list(self.root.glob('launch-*')), [])

    def test_app_exit_before_identity_keeps_its_completed_reply(self):
        process = self.bridge(exit_before_identity=True)
        out, errors = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(out, b'{"screen_recording":true,"device_control":true}\n')
        for row in (self.root / 'pids').read_text().splitlines():
            with self.assertRaises(ProcessLookupError):
                os.kill(int(row.split()[1]), 0)
        self.assertEqual(list(self.root.glob('launch-*')), [])

    def test_normal_app_exit_does_not_discard_its_pending_reply(self):
        process = self.bridge(finish_before_output=True)
        data = b'{"screen_recording":true,"device_control":true}\n'
        process.stdin.write(data)
        process.stdin.flush()
        deadline = time.monotonic() + 10
        while not (self.root / 'reader-ready').exists():
            if time.monotonic() > deadline:
                self.fail('independent reader did not open its pipes')
            time.sleep(.01)
        process.stdin.close()
        process.stdin = None
        out, errors = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(out, data)


if __name__ == '__main__':
    unittest.main()
