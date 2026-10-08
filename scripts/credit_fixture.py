"""Observe real shim detachment and repaint costs without wall-clock assertions (#118)."""
import threading
import time

from agent_fixture import AckBarrier


def completed(marker):
    """Wait for shell readiness; ninety seconds only bounds a stopped producer."""
    deadline = time.monotonic() + 90
    while not marker.exists():
        assert time.monotonic() < deadline, f'shell blocked: {marker}'
        time.sleep(.01)


class CreditObservation:
    """Reuse the real shim proxy to observe EOF and the cost of attempted recovery."""

    def __init__(self, state, session):
        self.condition = threading.Condition()
        self.disconnects = 0
        self.repaints = []
        self.proxy = AckBarrier(state, session, kind=None,
                                on_frame=self.frame, on_disconnect=self.disconnected)

    def frame(self, direction, body):
        if direction == 'output' and body[0] in (0x15, 0x1c):
            # Shim snapshots carry a type and u64 cursor; flags add one byte.
            with self.condition:
                self.repaints.append(len(body) - (10 if body[0] == 0x1c else 9))

    def disconnected(self):
        with self.condition:
            self.disconnects += 1
            self.condition.notify_all()

    def detached_after(self, count):
        """An actual shim EOF proves detachment; the deadline only bounds a hang."""
        with self.condition:
            assert self.condition.wait_for(lambda: self.disconnects > count, timeout=90), \
                'credit-starved relay never detached its shim socket'

    def close(self):
        self.proxy.close()
