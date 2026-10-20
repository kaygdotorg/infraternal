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
from process_identity import process_identity


def app_bundle(executable):
    """Only an app's real main executable is eligible for independent launch."""
    path = pathlib.Path(executable).resolve(strict=True)
    app = path.parent.parent.parent
    if path.parent.name != 'MacOS' or path.parent.parent.name != 'Contents' or app.suffix != '.app':
        raise ValueError('signed companion app required')
    return app


def open_command(executable, incoming, outgoing, errors, arguments, launch_record):
    # The marker prevents the companion's legacy SETEXEC responsibility hook:
    # LaunchServices already owns this launch, and must retain its attribution.
    command = ['/usr/bin/open', '-n', '-W', '-g', '--stdin', str(incoming),
               '--stdout', str(outgoing), '--stderr', str(errors)]
    for name in ('INFRATERNAL_DESKTOP_MEASURE',):
        if name in os.environ:
            command += ['--env', name + '=' + os.environ[name]]
    return command + [str(app_bundle(executable)), '--args', '--responsible-child',
                      '--launch-pid-file', str(launch_record)] + arguments


def run(executable, runtime, errors, pidlog, arguments):
    executable = pathlib.Path(executable).resolve(strict=True)
    capture = '--surface-capture' in arguments
    prefix = 'capture-' if capture else ''
    app_role = 'preflight' if '--check-permissions' in arguments else 'capture' if capture else 'native'
    with open(pidlog, 'a') as log:
        log.write(prefix + 'bridge ' + str(os.getpid()) + '\n')
    owned = set()
    births = {}
    opened = None
    incoming = outgoing = output_guard = None
    stdout_blocking = None
    writer_started = waiter_started = False
    cancelled = threading.Event()
    stopped, stop = os.pipe()
    os.set_blocking(stopped, False)
    os.set_blocking(stop, False)
    def wake():
        try:
            os.write(stop, b'x')
        except OSError:
            pass
    def interrupt(signum, frame):
        # Raising inside Thread.start or cleanup can abandon the independent
        # app. Wake the bounded I/O wait instead; cleanup cannot be interrupted.
        cancelled.set()
        wake()
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    with tempfile.TemporaryDirectory(prefix='launch-', dir=runtime) as directory:
        root = pathlib.Path(directory)
        # The bundle writes only its own PID here. The private directory and
        # exclusive create tie this record to this one LaunchServices request.
        launch_record = root / 'launched-pid'
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
            stdout_blocking = os.get_blocking(1)
            os.set_blocking(1, False)
            if cancelled.is_set():
                raise InterruptedError('companion bridge cancelled')
            opened = subprocess.Popen(open_command(executable, pathlib.Path('/dev/null') if '--check-permissions' in arguments else input_path, output_path, errors, arguments, launch_record),
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(pidlog, 'a') as log:
                log.write(prefix + 'launcher ' + str(opened.pid) + '\n')
            def wait_app():
                opened.wait()
                wake()
            waiter = threading.Thread(target=wait_app, daemon=True)
            waiter.start()
            waiter_started = True
            deadline = time.monotonic() + 10
            launched_pid = None
            while launched_pid is None:
                try:
                    record = launch_record.read_text()
                except FileNotFoundError:
                    record = ''
                if record.endswith('\n'):
                    rows = record.splitlines()
                    if len(rows) != 1 or not rows[0].isdecimal() or int(rows[0]) <= 0:
                        raise ValueError('app launch PID record invalid')
                    launched_pid = int(rows[0])
                    break
                if opened.poll() is not None:
                    raise ValueError('app launch PID unavailable')
                if time.monotonic() >= deadline:
                    raise TimeoutError('independent app launch unavailable')
                time.sleep(.01)
            with open(pidlog, 'a') as log:
                birth = process_identity(launched_pid)
                if birth is None:
                    # A short preflight may finish after publishing its PID
                    # but before its kernel identity is queried. It needs no
                    # cleanup authority once the PID has disappeared.
                    try:
                        os.kill(launched_pid, 0)
                    except ProcessLookupError:
                        log.write(f'completed {launched_pid}\n')
                    except PermissionError as error:
                        log.write(f'unverified {launched_pid}\n')
                        raise ValueError('app process identity unavailable') from error
                    else:
                        log.write(f'unverified {launched_pid}\n')
                        raise ValueError('app process identity unavailable')
                else:
                    owned.add(launched_pid)
                    births[launched_pid] = birth
                    log.write(f'{app_role} {launched_pid} {birth[1]} {birth[2]}\n')
            if cancelled.is_set():
                raise InterruptedError('companion bridge cancelled')
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
            writer_started = True
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
                    # A stopped reader must not trap cancellation in write(2).
                    # Both forwarding directions share the cancellation pipe.
                    while view and not cancelled.is_set():
                        ready = select.select([stopped], [1], [])
                        if stopped in ready[0]:
                            if cancelled.is_set():
                                break
                            # App completion wakes the reader too. Its buffered
                            # reply still belongs to the caller; consume only
                            # that wake, leaving any later cancellation visible.
                            try:
                                os.read(stopped, 1)
                            except BlockingIOError:
                                pass
                        if ready[1]:
                            try:
                                view = view[os.write(1, view):]
                            except BlockingIOError:
                                continue
                elif stopped in readable:
                    break
            if cancelled.is_set():
                raise InterruptedError('companion bridge cancelled')
            opened.wait(timeout=10)
            return opened.returncode
        finally:
            cancelled.set()
            wake()
            if writer_started:
                writer.join(timeout=1)
            elif incoming is not None:
                os.close(incoming)
            if output_guard is not None:
                os.close(output_guard)
            if outgoing is not None:
                os.close(outgoing)
            # An interrupted wrapper retires only the PID its child recorded;
            # the kernel birth value guards against reuse after that record.
            for pid in owned:
                if process_identity(pid) != births.get(pid):
                    continue
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if opened is not None and opened.poll() is None:
                opened.terminate()
                opened.wait(timeout=5)
            if waiter_started:
                waiter.join(timeout=1)
            os.close(stopped)
            os.close(stop)
            if stdout_blocking is not None:
                os.set_blocking(1, stdout_blocking)


if __name__ == '__main__':
    try:
        raise SystemExit(run(*sys.argv[1:5], sys.argv[5:]))
    except (OSError, ValueError, subprocess.SubprocessError):
        # Exceptions can contain input or launch environment; keep logs fixed.
        sys.stderr.write('Independent companion launch refused.\n')
        raise SystemExit(1)
