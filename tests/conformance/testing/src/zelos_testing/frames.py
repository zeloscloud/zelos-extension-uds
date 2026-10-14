"""Receiving and sending frames on a bus under test."""

import contextlib
import threading
import time
from collections.abc import Callable, Iterable, Iterator

import can
import pytest

# Set once by the plugin from the channel. SIMULATED: the nodes run under
# Renode, whose clock keeps pace with the host's only as long as the host can
# run the bench at full speed. TIME_SCALE: host seconds a wait may take per
# second of the node's time (--time-scale).
SIMULATED = False
TIME_SCALE = 1.0

# Waits end on the node's frames, so they run in its time whatever the host's.
# This much of its time bounds any one of them.
WAIT_S = 10.0

# How far a host timestamp can sit from the node's clock under Renode: the
# bridge writes a frame when the emulation reaches it, and the emulation runs
# ahead of or behind the host by whatever the host's scheduling allows. Over
# ten minutes on GitHub's 4-vCPU runners, gaps between a node's frames strayed
# up to 19 ms from its period with three nodes on the bench and 120 ms with five.
HOST_JITTER_S = 0.2


def bound(node_s: float) -> float:
    """Host seconds to allow for node_s of the node's time. A safety bound only."""
    return node_s * TIME_SCALE


def _receive(bus: can.BusABC, seconds: float, ids: Iterable[int] | None) -> Iterator[can.Message]:
    """Data frames for host `seconds`, oldest first, optionally only these IDs."""
    wanted = None if ids is None else set(ids)
    end = time.monotonic() + seconds
    while (left := end - time.monotonic()) > 0:
        msg = bus.recv(left)
        if msg is None or msg.is_error_frame or (wanted is not None and msg.arbitration_id not in wanted):
            continue
        yield msg


def until(bus: can.BusABC, done: Callable[[list[can.Message]], bool], node_s: float = WAIT_S, ids: Iterable[int] | None = None) -> list[can.Message]:
    """Data frames, oldest first, optionally only these IDs, until done(frames) holds.

    done should decide on frames the node sends on its own clock, so the wait is
    in the node's time; node_s only bounds it.
    """
    frames = []
    for msg in _receive(bus, bound(node_s), ids):
        frames.append(msg)
        if done(frames):
            return frames
    pytest.fail(f"not done within {node_s} s of node time ({bound(node_s):.0f} s here), after {len(frames)} frames")


def collect(bus: can.BusABC, seconds: float, ids: Iterable[int] | None = None) -> list[can.Message]:
    """Every data frame received for `seconds`, oldest first, optionally only these IDs."""
    return list(_receive(bus, seconds, ids))


def count(frames: list[can.Message], frame_id: int) -> int:
    """How many of frames are on frame_id."""
    return sum(m.arbitration_id == frame_id for m in frames)


def assert_period(gaps: list[float], period_s: float, tol: float):
    """Gaps between one node's frames keep its period_s.

    On hardware the mean is within tol (a fraction) of period_s, and no gap is
    a fifth late. Under Renode the host stamps carry HOST_JITTER_S of the
    host's scheduling, and stretch together when the host cannot keep up, so
    what holds there is that the node never stalled; a drop or a burst shows in
    its own counters and ratios, which the suites check in its time.
    """
    mean = sum(gaps) / len(gaps)
    if SIMULATED:
        assert max(gaps) < 2 * mean + HOST_JITTER_S, f"gaps {min(gaps):.4f}..{max(gaps):.4f} s, mean {mean:.4f} s"
    else:
        assert abs(mean - period_s) < tol * period_s, f"mean {mean * 1000:.2f} ms for {period_s * 1000:.0f} ms"
        assert max(gaps) < 1.2 * period_s, f"max {max(gaps) * 1000:.2f} ms for {period_s * 1000:.0f} ms"


class Periodic:
    """Send make_msg() every period_s while the block runs, as the node's peer would.

    make_msg is called for each frame, so it can advance a counter or pick up a
    changed value. A send failure is raised when the block exits.
    """

    def __init__(self, bus: can.BusABC, make_msg: Callable[[], can.Message], period_s: float):
        self.bus, self.make_msg, self.period_s = bus, make_msg, period_s
        self.sent = 0
        self._stop = threading.Event()
        self._error: Exception | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        if self._error is not None and exc[0] is None:
            raise self._error

    def _run(self):
        try:
            while not self._stop.is_set():
                self.bus.send(self.make_msg(), timeout=self.period_s)
                self.sent += 1
                self._stop.wait(self.period_s)
        except can.CanError as err:
            self._error = err


@contextlib.contextmanager
def play_unless_present(bus: can.BusABC, frame_id: int, make_msg: Callable[[], can.Message], period_s: float, window: Callable[[list[can.Message]], bool]):
    """Play the peer that sends frame_id for the block, unless one is on the bus.

    window(frames) holds once enough of the node's time has passed for the
    peer to have sent frame_id.
    """
    seen = until(bus, lambda frames: frames[-1].arbitration_id == frame_id or window(frames))
    if seen[-1].arbitration_id == frame_id:
        yield
        return
    with Periodic(bus, make_msg, period_s):
        yield
