"""Role: bridge private pipes to a signed app launched by LaunchServices, outside the SSH responsibility tree (#146)."""
import os
import pathlib
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time


def app_bundle(executable):
    """Only an app's real main executable is eligible for independent launch."""
    path = pathlib.Path(executable).resolve(strict=True)
    app = path.parent.parent.parent
    if path.parent.name != 'MacOS' or path.parent.parent.name != 'Contents' or app.suffix != '.app':
        raise ValueError('signed companion app required')
    return app


def open_command(executable, incoming, outgoing, errors, arguments):
    # The marker prevents the companion's legacy SETEXEC responsibility hook:
    # LaunchServices already owns this launch, and must retain its attribution.
    command = ['/usr/bin/open', '-n', '-W', '-g', '--stdin', str(incoming),
               '--stdout', str(outgoing), '--stderr', str(errors)]
    for name in ('INFRATERNAL_DESKTOP_MEASURE',):
        if name in os.environ:
            command += ['--env', name + '=' + os.environ[name]]
    return command + [str(app_bundle(executable)), '--args', '--responsible-child'] + arguments


def app_pids(executable):
    rows = subprocess.check_output(['/bin/ps', '-axo', 'pid=,comm='], text=True)
    return {int(parts[0]) for row in rows.splitlines()
            if len(parts := row.strip().split(None, 1)) == 2 and parts[1] == str(executable)}


def run(executable, runtime, errors, pidlog, arguments):
    executable = pathlib.Path(executable).resolve(strict=True)
    capture = '--surface-capture' in arguments
    prefix = 'capture-' if capture else ''
    with open(pidlog, 'a') as log:
        log.write(prefix + 'bridge ' + str(os.getpid()) + '\n')
    before = app_pids(executable)
    owned = set()
    opened = None
    incoming = outgoing = output_guard = None
    cancelled = threading.Event()
    stopped, stop = os.pipe()
    def wake():
        try:
            os.write(stop, b'x')
        except OSError:
            pass
    def interrupt(signum, frame):
        raise InterruptedError('companion bridge cancelled')
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    with tempfile.TemporaryDirectory(prefix='launch-', dir=runtime) as directory:
        root = pathlib.Path(directory)
        input_path, output_path = root / 'stdin', root / 'stdout'
        os.mkfifo(input_path, 0o600)
        os.mkfifo(output_path, 0o600)
        # Hold both FIFO ends until the independently launched app opens them.
        # The input descriptor is then owned by exactly one forwarding thread;
        # EOF from Rust closes it and lets native cleanup restore the window.
        incoming = os.open(input_path, os.O_RDWR)
        output_guard = os.open(output_path, os.O_RDWR)
        outgoing = os.open(output_path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            opened = subprocess.Popen(open_command(executable, pathlib.Path('/dev/null') if '--check-permissions' in arguments else input_path, output_path, errors, arguments),
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(pidlog, 'a') as log:
                log.write(prefix + 'launcher ' + str(opened.pid) + '\n')
            def wait_app():
                opened.wait()
                wake()
            waiter = threading.Thread(target=wait_app, daemon=True)
            waiter.start()
            deadline = time.monotonic() + 10
            while not owned:
                owned = app_pids(executable) - before
                if owned or opened.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError('independent app launch unavailable')
                time.sleep(.01)
            with open(pidlog, 'a') as log:
                for pid in owned:
                    log.write(('capture' if capture else 'native') + ' ' + str(pid) + '\n')
            def forward_input():
                try:
                    while not cancelled.is_set():
                        readable = select.select([0, stopped], [], [])[0]
                        if stopped in readable:
                            break
                        data = os.read(0, 65536)
                        if not data:
                            break
                        view = memoryview(data)
                        while view and not cancelled.is_set():
                            ready = select.select([stopped], [incoming], [])
                            if stopped in ready[0]:
                                break
                            if ready[1]:
                                count = os.write(incoming, view)
                                view = view[count:]
                except (OSError, ValueError):
                    pass
                finally:
                    os.close(incoming)
            os.set_blocking(incoming, False)
            writer = threading.Thread(target=forward_input, daemon=True)
            writer.start()
            while True:
                readable = select.select([outgoing, stopped], [], [])[0]
                if outgoing in readable:
                    data = os.read(outgoing, 65536)
                    if not data:
                        break
                    # A PID can appear before LaunchServices has opened stdout.
                    # Release the guard only after the app proves a writer exists.
                    if output_guard is not None:
                        os.close(output_guard)
                        output_guard = None
                    view = memoryview(data)
                    while view:
                        view = view[os.write(1, view):]
                elif stopped in readable:
                    break
            opened.wait(timeout=10)
            return opened.returncode
        finally:
            cancelled.set()
            wake()
            if 'writer' in locals():
                writer.join(timeout=1)
            elif incoming is not None:
                os.close(incoming)
            if output_guard is not None:
                os.close(output_guard)
            if outgoing is not None:
                os.close(outgoing)
            # An interrupted wrapper must also retire its independently owned
            # app. Only PIDs first seen in this launch are eligible for signals.
            for pid in owned & app_pids(executable):
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if opened is not None and opened.poll() is None:
                opened.terminate()
                opened.wait(timeout=5)
            if 'waiter' in locals():
                waiter.join(timeout=1)
            os.close(stopped)
            os.close(stop)


if __name__ == '__main__':
    try:
        raise SystemExit(run(*sys.argv[1:5], sys.argv[5:]))
    except (OSError, ValueError, subprocess.SubprocessError):
        # Exceptions can contain input or launch environment; keep logs fixed.
        sys.stderr.write('Independent companion launch refused.\n')
        raise SystemExit(1)
