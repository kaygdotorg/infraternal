"""A real one-run waterfall must not leave newly created detached PTY shims."""
from pathlib import Path
import os
import subprocess

binary = Path(os.environ.get('SIGNIN_MEASURE_BINARY', 'target/x86_64-unknown-linux-musl/release/infraternal')).resolve()
def shim_pids():
    result = set()
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            if (process / 'exe').resolve() == binary and b'\x00__shim\x00' in (process / 'cmdline').read_bytes():
                result.add(int(process.name))
        except OSError:
            pass
    return result
before = shim_pids()
label = 'waterfall-cleanup'
environment = dict(os.environ, TRACER_TEST_PORT='4641', SIGNIN_MEASURE_BINARY=str(binary), SIGNIN_MEASURE_CASES='0', SIGNIN_MEASURE_RUNS='1', SIGNIN_MEASURE_RESULTS=f'target/cleanup-{label}.json')
with open(f'target/cleanup-{label}-waterfall.log', 'w') as log:
    subprocess.run(['bun', 'scripts/browser-auth/measure-returning-signin.mjs'], env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
leaked = shim_pids() - before
print(f'new detached session shims after one real waterfall: {len(leaked)}', flush=True)
assert not leaked, 'waterfall leaked detached PTY shims'
print('PASS')
