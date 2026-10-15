#!/usr/bin/env python3
"""Drain private numeric host traces without sharing the workload interpreter [D270]."""
import multiprocessing
import os
from pathlib import Path

CONTEXT = multiprocessing.get_context('fork')


class Drain:
    """Implement the trace reader's start/join seam with an owned child process."""
    def __init__(self, target, daemon):
        self.observer = target.__self__
        self.target = target
        self.receiver, self.sender = CONTEXT.Pipe(duplex=False)
        self.process = CONTEXT.Process(target=self.run, daemon=daemon)
        self.started = False

    def run(self):
        self.receiver.close()
        # Socket copies must never retain synthetic viewers after the driver
        # closes them. This child uses only its trace fd and numeric result pipe.
        for path in Path('/proc/self/fd').iterdir():
            try:
                if os.readlink(path).startswith('socket:['):
                    os.close(int(path.name))
            except OSError:
                pass
        try:
            self.target()
        except Exception as error:
            self.observer.error = type(error).__name__
        self.sender.send((self.observer.events, self.observer.error))
        self.sender.close()

    def start(self):
        self.process.start()
        self.started = True
        self.sender.close()

    def join(self):
        if not self.started:
            return
        try:
            if self.receiver.poll(10):
                self.observer.events, self.observer.error = self.receiver.recv()
            else:
                self.observer.error = 'numeric reader did not stop'
                self.process.terminate()
        except (EOFError, OSError):
            self.observer.error = 'numeric reader result missing'
        finally:
            self.receiver.close()
            self.process.join(timeout=10)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=10)
                self.observer.error = 'numeric reader cleanup needed'
            if self.process.exitcode:
                self.observer.error = 'numeric reader exited unsuccessfully'
