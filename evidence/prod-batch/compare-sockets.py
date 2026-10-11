#!/usr/bin/env python3
"""Run unchanged dev/merged socket cases together in one load window for #118/#154."""
from pathlib import Path
import datetime, json, os, subprocess, time
root = Path('/home/kayg/.cache/codex-scratch/prod-batch')
roles = {
 'dev': (root/'dev-target/debug/deps/infraternal_server-0a5862be3bc4afdd', root/'baseline/crates/infraternal-server', root/'dev-target'),
 'merged': (root/'target/debug/deps/infraternal_server-4da00085bcd99910', Path('/home/kayg/Developer/infraternal/.worktrees/prod-batch/crates/infraternal-server'), root/'target'),
}
cases = {
 'liveness': 'auth::tests::socket_tests::claude_review_visible_liveness::claude_review_watch_expires_host_made_visible_by_membership_edit',
 'headroom': 'auth::tests::socket_tests::scale::review_mesh_headroom_snapshot_does_not_close_shared_socket',
}
for label, case in cases.items():
 print(json.dumps(dict(case=label, phase='start', utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), load=Path('/proc/loadavg').read_text().strip())), flush=True)
 children=[]
 for role,(binary,cwd,target) in roles.items():
  env=dict(os.environ,CARGO_TARGET_DIR=str(target),RUST_TEST_THREADS='1',TRACER_TEST_PORT='5799',INFRATERNAL_TEST_RTT='300')
  log=(root/'logs'/f'compare-{label}-{role}.log').open('w')
  start=time.monotonic()
  child=subprocess.Popen([str(binary),'--exact',case,'--nocapture'],cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT)
  children.append((role,child,log,start))
 for role,child,log,start in children:
  code=child.wait(); log.close()
  print(json.dumps(dict(case=label,role=role,exit=code,elapsed_s=round(time.monotonic()-start,3),load=Path('/proc/loadavg').read_text().strip())),flush=True)
