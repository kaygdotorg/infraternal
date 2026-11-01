#!/usr/bin/env python3
"""Reproduce a restart child timeout retaining its short socket root (#271).

Run with the built infraternal unit-test executable, not the production CLI.
The private copy under /tmp deliberately fails executable ancestry admission.
The existing outer fixture then reaches its own bounded child-termination path.
Only roots identified through that child's open socket descriptors are checked
and removed, so other jobs' temporary directories are never swept.

SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def children(pid):
    result = set()
    for task in Path(f'/proc/{pid}/task').glob('*'):
        try:
            result.update(map(int, (task / 'children').read_text().split()))
        except FileNotFoundError:
            pass
    return result


def socket_roots(pid):
    inodes = set()
    for descriptor in Path(f'/proc/{pid}/fd').glob('*'):
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            inodes.add(target[8:-1])
    roots = set()
    for line in Path('/proc/net/unix').read_text().splitlines()[1:]:
        fields = line.split(maxsplit=7)
        if len(fields) != 8 or fields[6] not in inodes:
            continue
        path = Path(fields[7])
        if (path.name == 'control.sock' and path.parent.name == 'restart'
                and path.parent.parent.parent == Path('/tmp')
                and path.parent.parent.name.startswith('ir-')):
            roots.add(path.parent.parent)
    return roots


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unit_test_binary', type=Path)
    args = parser.parse_args()
    owned_roots = set()
    with tempfile.TemporaryDirectory(prefix='j29-timeout-', dir='/tmp') as scratch:
        image = Path(scratch) / 'unit-tests'
        shutil.copyfile(args.unit_test_binary, image)
        image.chmod(0o700)
        environment = dict(os.environ)
        environment['INFRATERNAL_TEST_STATE_ROOT'] = str(
            Path(scratch) / ('deep-worktree-' * 12))
        name = 'restart::tests::restart_request_logs_kernel_peer_target_and_cold_outcome'
        child = subprocess.Popen([str(image), '--exact', name, '--nocapture'],
                                 env=environment, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and child.poll() is None:
                for pid in children(child.pid):
                    owned_roots.update(socket_roots(pid))
                if owned_roots:
                    break
                time.sleep(0.02)
            output, _ = child.communicate(timeout=90)
            print(output, flush=True)
            assert owned_roots, 'did not observe the test-owned control socket'
            assert child.returncode != 0 and 'exceeded 60s' in output, output
            leftovers = sorted(str(root) for root in owned_roots if root.exists())
            assert not leftovers, f'timed-out fixture left private socket roots: {leftovers}'
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            for root in owned_roots:
                shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
