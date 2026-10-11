#!/usr/bin/env python3
"""Exercise the compiled release CLI against an existing private SQLite server and real TTY [202,226]."""
import json
import os
from pathlib import Path
import pty
import select
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ['INFRATERNAL_BIN'])

class ChannelCli(unittest.TestCase):
    def test_existing_server_channel_and_skill(self):
        scratch=Path(os.environ['CARGO_TARGET_DIR'])
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            state=Path(directory)
            database=state/'infraternal.sqlite'
            connection=sqlite3.connect(database)
            connection.executescript((ROOT/'crates/infraternal-server/migrations/0014_plugin_settings.sql').read_text())
            connection.executescript((ROOT/'crates/infraternal-server/migrations/0020_release_channel.sql').read_text())
            connection.close()
            database.chmod(0o600)
            def run(*args):
                return subprocess.run([str(BINARY),'server','--data',str(state),*args],text=True,capture_output=True,timeout=15)
            self.assertEqual(json.loads(run('channel','--json').stdout)['channel'],'stable')
            human=run('channel')
            self.assertEqual(human.returncode,0,human.stderr)
            for section in ['State', 'Detail', 'Next']:
                self.assertRegex(human.stdout,r'(?m)^  '+section+r'\s+\S')
            self.assertIn('Release channel: stable',human.stdout)
            print('CLI_HUMAN default=stable\n'+human.stdout,flush=True)
            for args in [('channel','edge'),('channel','edge','--json')]:
                response=run(*args)
                self.assertEqual(response.returncode,1)
                self.assertIn('unreviewed',response.stderr+response.stdout)
                self.assertEqual(json.loads(run('channel','--json').stdout)['channel'],'stable')
            response=run('channel','edge','--yes','--json')
            self.assertEqual(response.returncode,0,response.stderr)
            self.assertEqual(json.loads(response.stdout)['channel'],'edge')
            self.assertEqual(run('channel','stable').returncode,0)
            for answer,expected in [(b'no\n','stable'),(b'yes\n','edge')]:
                master,slave=pty.openpty()
                process=subprocess.Popen([str(BINARY),'server','--data',str(state),'channel','edge','--json'],stdin=slave,stderr=slave,stdout=subprocess.PIPE,text=True)
                os.close(slave)
                try:
                    prompt=b''
                    while b'Type yes to confirm:' not in prompt:
                        self.assertTrue(select.select([master],[],[],15)[0],prompt)
                        prompt+=os.read(master,4096)
                    self.assertIn(b'unreviewed',prompt)
                    os.write(master,answer)
                    output,_=process.communicate(timeout=15)
                    self.assertEqual(process.returncode,0 if expected=='edge' else 1)
                    self.assertEqual(json.loads(run('channel','--json').stdout)['channel'],expected)
                    print('CLI_CONFIRM '+json.dumps({'tty':True,'answer':answer.decode().strip(),'exit':process.returncode,'persisted':expected,'prompt':prompt.decode()}),flush=True)
                finally:
                    if process.poll() is None:process.kill();process.wait()
                    os.close(master)
            self.assertEqual(run('channel','stable').returncode,0)
            connection=sqlite3.connect(database)
            connection.execute("UPDATE plugin_settings SET enabled=0 WHERE role='server' AND plugin='release'")
            connection.commit();connection.close()
            self.assertNotEqual(run('channel','edge','--yes').returncode,0)
            absent=state/'absent'
            response=subprocess.run([str(BINARY),'server','--data',str(absent),'channel','--json'],text=True,capture_output=True,timeout=15)
            self.assertEqual(response.returncode,1)
            self.assertFalse(absent.exists(),'channel action must never create a server')
        for action in ['release.channel.get','release.channel.set','release.latest']:
            response=subprocess.run([str(BINARY),'skill',action,'--json'],text=True,capture_output=True,timeout=15)
            self.assertEqual(response.returncode,0,response.stderr)
            self.assertEqual(json.loads(response.stdout)['action'],action)
        expected = os.environ.get('INFRATERNAL_EXPECTED_CHANNEL', 'stable')
        reported=subprocess.check_output([str(BINARY),'--version'],text=True)
        self.assertIn('('+expected+')',reported)
        print('CLI_VERSION '+reported.strip(),flush=True)

if __name__=='__main__':unittest.main()
