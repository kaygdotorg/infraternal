"""Role: check independent app launch arguments and real pipe/EOF forwarding without accessing a desktop (#146)."""
import importlib.util
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = pathlib.Path(__file__).with_name('launch-companion.py')
spec = importlib.util.spec_from_file_location('companion_launch', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SCRATCH = pathlib.Path.home() / '.cache/codex-scratch/app-windows-latency-r3b/launcher-tests'
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
        command = module.open_command(self.native, 'in', 'out', 'err', ['--surface-capture'])
        self.assertEqual(command[:4], ['/usr/bin/open', '-n', '-W', '-g'])
        self.assertEqual(command[-4:], [str(self.native.parent.parent.parent), '--args', '--responsible-child', '--surface-capture'])
        self.assertNotIn(str(self.native), command)
        self.assertEqual(command[4:10], ['--stdin', 'in', '--stdout', 'out', '--stderr', 'err'])

    def bridge(self):
        # Substitute only the platform launcher. Everything after it uses real
        # processes, FIFO backpressure, standard pipes and native EOF behavior.
        runner = '''import importlib.util,pathlib,subprocess,sys
spec=importlib.util.spec_from_file_location('launch',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
children=[];real=m.subprocess.Popen
def launch(*a,**kw):
 p=real(*a,**kw);children.append(p);return p
m.subprocess.Popen=launch
m.app_pids=lambda executable:{p.pid for p in children if p.poll() is None}
def command(executable,incoming,outgoing,errors,arguments):
 return [sys.executable,'-c',"import sys; a=open(sys.argv[1],'rb',buffering=0); b=open(sys.argv[2],'wb',buffering=0); data=a.read(); b.write(data); a.close(); b.close()",str(incoming),str(outgoing)]
m.open_command=command
raise SystemExit(m.run(sys.argv[2],sys.argv[3],sys.argv[3]+'/errors',sys.argv[3]+'/pids',[]))
'''
        return subprocess.Popen([sys.executable, '-c', runner, str(SOURCE), str(self.native), str(self.root)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_stream_bytes_and_eof_reach_the_independent_app(self):
        process = self.bridge()
        data = bytes(range(256)) * 8192
        out, errors = process.communicate(data, timeout=15)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(out, data)
        self.assertEqual(list(self.root.glob('launch-*')), [])
        for row in (self.root / 'pids').read_text().splitlines():
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


if __name__ == '__main__':
    unittest.main()
